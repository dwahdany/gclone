// gclone web — the page. Vanilla, one file, no network but this server.
// Everything from the vault (names, paths, file text) reaches the page as text nodes and
// attribute values through the DOM API; nothing is ever parsed as markup.
// No name from the vault is put where the browser keeps it beyond the tab: the address and
// the title never change (the place in the vault is in history.state), and files are
// addressed by the opaque ids the server hands out.
//
// The page has one seam, `provider`: where the answers and the files come from. `gclone web`
// uses the one below (this server). The hosted viewer runs the same script over a vault it
// reads in the browser, and sets `window.gcloneProvider` before the script starts.
'use strict';
(() => {
  const provider = window.gcloneProvider || {
    // (name, params, options) -> Promise<object>: one call of the viewer's API.
    api: httpApi,
    // (id, download) -> string: the address of a file's bytes, by the id `stat` gave.
    fileUrl: httpFileUrl,
    // Said when a request gets no answer at all.
    unreachable: 'The viewer does not answer. Is `gclone web` still running in its terminal?',
    // true: places live in the page's memory, and history.state holds no name either.
    privateAddress: false,
    // false: a card with "Open" (a tab of its own) in place of the PDF frame.
    pdfInline: true,
    // (kind) -> boolean: whether a file of this kind is offered "Open in a new tab".
    openInTab: () => true,
    // false: download links are plain links, which the answer's Content-Disposition turns
    // into downloads (a browser may fetch a `download` link past a Service Worker).
    downloadAttribute: true,
  };
  const $ = (id) => document.getElementById(id);
  const SVG = 'http://www.w3.org/2000/svg'; // a namespace name, not an address
  const PAGE = 2000; // entries per request
  const OVERSCAN = 8; // rows drawn beyond the visible ones
  const TEXT_PREVIEW = 512 * 1024; // bytes of a text file that are shown
  const PREVIEWS = new Set(['image', 'pdf', 'audio', 'video', 'text']);
  const narrow = window.matchMedia('(max-width: 719px)');

  const dom = {
    list: $('list'), rows: $('rows'), canvas: $('canvas'), empty: $('empty'),
    crumbs: $('crumbs'), search: $('search'), count: $('count'), summary: $('summary'),
    notice: $('notice'), noticeText: $('notice-text'), viewer: $('viewer'),
    viewerBody: $('viewer-body'), info: $('info'), infoBtn: $('info-btn'),
  };

  // What the list shows: a folder, or search results.
  const view = {
    mode: 'dir', // 'dir' | 'search'
    path: '', // the folder
    q: '', // the search
    entries: [], // loaded so far; in a folder `total` may be larger while pages arrive
    entriesDir: '', // the folder `entries` belong to (search results carry their paths)
    total: 0,
    more: false, // search: the server has more matches
    active: -1,
    loaded: null, // key of what `entries` holds
    error: false,
  };
  let sort = { key: 'name', desc: false };
  let generation = 0; // of list requests: late answers are dropped
  let lastDir = ''; // where "clear the search" returns to
  let shown = null; // the file in the viewer: { path, name }
  let viewerGen = 0;
  let vaultName = 'Vault';
  let lastInfo = null; // the vault summary as last received
  let busy = 0;
  let searchTimer = 0;

  try {
    const saved = JSON.parse(localStorage.getItem('gclone.sort') || 'null');
    if (saved && ['name', 'size', 'mtime'].includes(saved.key)) sort = { key: saved.key, desc: !!saved.desc };
  } catch (_) { /* no storage: the default order */ }

  // ---- small helpers --------------------------------------------------------------------------

  function el(tag, props, ...children) {
    const node = document.createElement(tag);
    for (const [name, value] of Object.entries(props || {})) {
      if (value === false || value == null) continue;
      if (name === 'class') node.className = value;
      else if (name === 'text') node.textContent = value;
      else node.setAttribute(name, value === true ? '' : value);
    }
    node.append(...children.filter((c) => c != null));
    return node;
  }

  function icon(name, cls) {
    const svg = document.createElementNS(SVG, 'svg');
    svg.setAttribute('class', cls ? `i ${cls}` : 'i');
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS(SVG, 'use');
    use.setAttribute('href', `#i-${name}`);
    svg.append(use);
    return svg;
  }

  const ICONS = { folder: 'folder', image: 'image', video: 'video', audio: 'audio', pdf: 'pdf', text: 'text', archive: 'archive', file: 'file' };
  const KINDS = { folder: 'Folder', image: 'Image', video: 'Video', audio: 'Audio', pdf: 'PDF document', text: 'Text', archive: 'Archive', file: 'File' };
  const typeIcon = (kind) => icon(ICONS[kind] || 'file', `t-${kind}`);

  function formatSize(n) {
    if (n == null) return '';
    if (n < 1024) return `${n} B`;
    const units = ['KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'];
    let v = n / 1024;
    let u = 0;
    while (v >= 1024 && u < units.length - 1) { v /= 1024; u += 1; }
    let r = Math.round(v * 10) / 10;
    if (r >= 1024 && u < units.length - 1) { r = 1; u += 1; }
    return `${Number.isInteger(r) ? r : r.toFixed(1)} ${units[u]}`;
  }

  const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  const dateOnly = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });
  function formatTime(ms, short) {
    if (ms == null) return '';
    const date = new Date(ms);
    if (Number.isNaN(date.getTime())) return '';
    return (short ? dateOnly : dateTime).format(date);
  }

  function ago(ms) {
    const s = Math.max(0, (Date.now() - ms) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return `${Math.floor(s / 60)} min ago`;
    if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
    if (s < 30 * 86400) return `${Math.floor(s / 86400)} d ago`;
    return formatTime(ms, true);
  }

  const count = (n, one, many) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
  const parentOf = (path) => (path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '');
  const nameOf = (path) => path.slice(path.lastIndexOf('/') + 1);
  const join = (dir, name) => (dir ? `${dir}/${name}` : name);
  // Rows know their folder: `view.path` already names the next one while that is loading.
  const pathOf = (entry) => (entry.path != null ? entry.path : join(view.entriesDir, entry.name));

  // A name as it is shown: every character of it, on one line, in the order it has. Line
  // breaks, tabs and other control characters become their pictures (U+2400…); spaces are kept
  // by `white-space: pre`. The characters that turn the text around them (U+202E and its kin)
  // become U+FFFD: `invoice<U+202E>fdp.exe` must not read "invoiceexe.pdf". Tooltips and
  // labels keep the name as it is.
  const show = (name) => name
    .replace(/[\u0000-\u001f\u007f]/g, (c) => (c === '\u007f' ? '\u2421' : String.fromCharCode(0x2400 + c.charCodeAt(0))))
    .replace(/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '\ufffd');

  // A sentence with `commands` in it: text nodes and <code> elements, never markup.
  function prose(node, text) {
    node.replaceChildren(...String(text || '').split('`').map((part, i) => (
      i % 2 ? el('code', { text: part }) : document.createTextNode(part))));
    return node;
  }

  // ---- places ---------------------------------------------------------------------------------
  // Where the page is — { dir }, { file } (shown over its folder) or { search } — lives in
  // history.state: reload, back and forward work, and neither the address nor the title ever
  // carries a name from the vault into the browser's history.

  // With `provider.privateAddress` not even history.state holds a place — session history
  // outlives the tab in the browser's session files. The places are in `places`, in this
  // page's memory; an entry holds its number there and `epoch`, which names this run of the
  // script. An entry of another run (before a reload) leads to the vault's root.
  const places = [];
  const epoch = provider.privateAddress
    ? Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('') : null;
  const ownEntry = () => !provider.privateAddress || !!(history.state && history.state.e === epoch);

  // What an entry keeps of its place: the place itself, or its number in `places`.
  function kept(place, replace) {
    if (!provider.privateAddress) return place;
    const n = replace && ownEntry() ? history.state.n : places.length;
    places[n] = place;
    return { e: epoch, n };
  }

  function where() {
    const state = provider.privateAddress ? (ownEntry() && places[history.state.n]) || null : history.state;
    if (state && typeof state.search === 'string' && state.search.trim()) return { search: state.search.trim() };
    if (state && typeof state.file === 'string' && state.file) return { file: state.file };
    if (state && typeof state.dir === 'string') return { dir: state.dir };
    return { dir: '' };
  }

  const samePlace = (a, b) => a.dir === b.dir && a.file === b.file && a.search === b.search;
  const placeOf = (entry) => (entry.dir ? { dir: pathOf(entry) } : { file: pathOf(entry) });
  const depth = () => (ownEntry() && history.state && history.state.depth) || 0;
  // This entry began a search from inside the page, so "back" ends it.
  const began = () => !!(ownEntry() && history.state && history.state.began);

  function navigate(place, replace) {
    if (samePlace(place, where())) {
      route();
      return;
    }
    if (replace) history.replaceState({ ...kept(place, true), depth: depth(), began: began() }, '');
    else history.pushState({ ...kept(place, false), depth: depth() + 1, began: place.search != null }, '');
    route();
  }

  // A link to a place. Its address is the page itself: a plain click is handled here, and a
  // new tab starts at the vault's root.
  function link(place, props, ...children) {
    const node = el('a', { href: './', ...props }, ...children);
    node.place = place;
    return node;
  }

  // Files are fetched by the id `api/stat` gives (here: the path, sealed by the server).
  function httpFileUrl(id, download) {
    return `file?id=${encodeURIComponent(id)}${download ? '&dl=1' : ''}`;
  }
  const fileUrl = (id, download) => provider.fileUrl(id, download);

  // Out of the search, to the folder it was started from.
  function leaveSearch() {
    clearTimeout(searchTimer);
    dom.search.value = '';
    if (view.mode !== 'search') return;
    if (began()) history.back();
    else navigate({ dir: lastDir }, true);
  }

  // ---- server ---------------------------------------------------------------------------------

  async function explain(res) {
    let text = '';
    try { text = (await res.text()).trim(); } catch (_) { /* no body */ }
    return text || `The viewer answered with status ${res.status}.`;
  }

  async function request(url, options) {
    let res;
    try {
      res = await fetch(url, { cache: 'no-store', credentials: 'same-origin', ...options });
    } catch (_) {
      throw new Error(provider.unreachable);
    }
    if (!res.ok) throw new Error(await explain(res));
    return res;
  }

  async function httpApi(name, params, options) {
    const query = params ? `?${new URLSearchParams(params)}` : '';
    const res = await request(`api/${name}${query}`, options);
    return res.json();
  }
  const api = (name, params, options) => provider.api(name, params, options);

  function setBusy(on) {
    busy = Math.max(0, busy + (on ? 1 : -1));
    if (busy === 0) document.body.classList.remove('busy');
    else setTimeout(() => { if (busy > 0) document.body.classList.add('busy'); }, 150);
  }

  let noticeTimer = 0;
  function notify(text, kind, lasting) {
    clearTimeout(noticeTimer);
    if (!text) {
      dom.notice.hidden = true;
      return;
    }
    prose(dom.noticeText, text);
    dom.notice.className = kind === 'error' ? 'notice error' : 'notice';
    dom.notice.setAttribute('role', kind === 'error' ? 'alert' : 'status');
    dom.notice.hidden = false;
    if (!lasting) noticeTimer = setTimeout(() => { dom.notice.hidden = true; }, 5000);
    schedulePaint();
  }

  // ---- the list -------------------------------------------------------------------------------

  const rowHeight = () => (view.mode === 'search' || narrow.matches ? 56 : 40);
  let drawn = { start: -1, end: -1, height: 0 };
  let paintQueued = false;

  function schedulePaint() {
    if (paintQueued) return;
    paintQueued = true;
    requestAnimationFrame(() => { paintQueued = false; paint(false); });
  }

  function buildRow(i, height) {
    const entry = view.entries[i];
    const path = pathOf(entry);
    const meta = entry.dir ? '' : `${formatSize(entry.size)} · ${formatTime(entry.mtime_ms, true)}`;
    let sub = el('span', { class: 'sub', text: meta });
    if (view.mode === 'search') {
      // The folder of a match is what tells two matches apart: when it does not fit, it is
      // its beginning that is cut (`.where`), and the row's tooltip has all of it.
      const parent = parentOf(path);
      const where = parent ? `in ${show(parent)}` : `in ${show(vaultName)}`;
      sub = el('span', { class: 'sub where', title: parent || vaultName },
        el('bdi', { text: narrow.matches && meta ? `${where} · ${formatSize(entry.size)}` : where }));
    }
    const row = el('div', {
      class: i === view.active ? 'row active' : 'row',
      role: 'row',
      id: `row-${i}`,
      'aria-rowindex': String(i + 2),
      'aria-selected': i === view.active ? 'true' : 'false',
      'data-i': String(i),
    },
    el('div', { class: 'c-name', role: 'gridcell' },
      typeIcon(entry.kind),
      el('div', { class: 'names' },
        // The kind in words, for those who do not see the icon.
        link(placeOf(entry), { class: 'name', tabindex: '-1', title: entry.name },
          el('span', { class: 'sr', text: `${KINDS[entry.kind] || 'File'}: ` }), show(entry.name)),
        sub)),
    el('div', { class: 'c-size', role: 'gridcell', text: entry.dir ? '—' : formatSize(entry.size) }),
    el('div', { class: 'c-time', role: 'gridcell', text: entry.dir ? '' : formatTime(entry.mtime_ms, false) }));
    row.style.transform = `translateY(${i * height}px)`;
    return row;
  }

  // Draws the rows in and near the viewport — never more, however long the list is.
  function paint(force) {
    const height = rowHeight();
    const n = view.entries.length;
    const top = dom.rows.scrollTop;
    const start = Math.max(0, Math.floor(top / height) - OVERSCAN);
    const end = Math.min(n, Math.ceil((top + dom.rows.clientHeight) / height) + OVERSCAN);
    if (!force && start === drawn.start && end === drawn.end && height === drawn.height) return;
    drawn = { start, end, height };
    const rows = document.createDocumentFragment();
    for (let i = start; i < end; i += 1) rows.append(buildRow(i, height));
    dom.canvas.replaceChildren(rows);
  }

  function layout() {
    const total = Math.max(view.total, view.entries.length);
    dom.list.classList.toggle('two-line', rowHeight() === 56);
    dom.canvas.style.height = `${total * rowHeight()}px`;
    dom.list.style.setProperty('--sb', `${dom.rows.offsetWidth - dom.rows.clientWidth}px`);
    dom.list.setAttribute('aria-rowcount', String(total + 1));
    paint(true);
  }

  function setActive(i, reveal) {
    const n = view.entries.length;
    view.active = n === 0 || i === -1 ? -1 : Math.max(0, Math.min(n - 1, i));
    if (view.active >= 0) dom.list.setAttribute('aria-activedescendant', `row-${view.active}`);
    else dom.list.removeAttribute('aria-activedescendant');
    dom.list.classList.toggle('has-active', view.active >= 0);
    if (reveal && view.active >= 0) {
      const height = rowHeight();
      const top = view.active * height;
      if (top < dom.rows.scrollTop) dom.rows.scrollTop = top;
      else if (top + height > dom.rows.scrollTop + dom.rows.clientHeight) dom.rows.scrollTop = top + height - dom.rows.clientHeight;
    }
    paint(true);
  }

  function showEmpty(iconName, title, text) {
    dom.empty.hidden = !title;
    if (!title) return;
    $('empty-icon').firstElementChild.setAttribute('href', `#i-${iconName}`);
    $('empty-title').textContent = title;
    prose($('empty-text'), text);
  }

  function renderCrumbs() {
    const items = [];
    const crumb = (label, place, current) => el('li', null, current
      ? el('span', { 'aria-current': 'page', title: label, text: show(label) })
      : link(place, { title: label, text: show(label) }));
    if (view.mode === 'search') {
      items.push(crumb(vaultName, { dir: '' }, false));
      items.push(crumb(`Search: “${view.q}”`, null, true));
    } else {
      const parts = view.path ? view.path.split('/') : [];
      items.push(crumb(vaultName, { dir: '' }, parts.length === 0));
      parts.forEach((part, i) => {
        items.push(crumb(part, { dir: parts.slice(0, i + 1).join('/') }, i === parts.length - 1));
      });
    }
    dom.crumbs.replaceChildren(...items);
    // The end of the path is what matters: the list scrolls, and starts at its end.
    dom.crumbs.scrollLeft = dom.crumbs.scrollWidth;
    fadeCrumbs();
  }

  // Where the path's beginning is scrolled out of view, it fades out instead of being cut.
  function fadeCrumbs() {
    dom.crumbs.classList.toggle('cut', dom.crumbs.scrollLeft > 0);
  }

  function renderSort() {
    for (const key of ['name', 'size', 'mtime']) {
      const header = $(`h-${key}`);
      if (key === sort.key) header.setAttribute('aria-sort', sort.desc ? 'descending' : 'ascending');
      else header.removeAttribute('aria-sort');
    }
  }

  function renderCount() {
    const n = view.entries.length;
    if (view.error) dom.count.textContent = '';
    else if (view.mode === 'search') {
      dom.count.textContent = view.more
        ? `The first ${count(n, 'match', 'matches')} — there are more: refine the search`
        : count(n, 'match', 'matches');
    } else if (n < view.total) dom.count.textContent = `${n.toLocaleString()} of ${count(view.total, 'item', 'items')} loaded…`;
    else dom.count.textContent = count(view.total, 'item', 'items');
  }

  const dirKey = (path) => `dir\n${path}\n${sort.key}\n${sort.desc}`;
  const searchKey = (q) => `search\n${q}\n${sort.key}\n${sort.desc}`;
  const order = () => ({ sort: sort.key, order: sort.desc ? 'desc' : 'asc' });

  function failList(error) {
    view.entries = [];
    view.total = 0;
    view.more = false;
    view.error = true;
    view.loaded = null;
    layout();
    renderCount();
    showEmpty('info', 'This cannot be shown', error.message);
  }

  async function loadDir(path, select) {
    const mine = ++generation;
    const key = dirKey(path);
    Object.assign(view, { mode: 'dir', path, q: '', more: false, error: false });
    lastDir = path;
    renderCrumbs();
    setBusy(true);
    try {
      let offset = 0;
      for (;;) {
        const page = await api('list', { path, ...order(), offset: String(offset), limit: String(PAGE) });
        if (mine !== generation) return;
        if (offset === 0) {
          view.entries = page.entries;
          view.entriesDir = path;
          view.total = page.total;
          view.loaded = key;
          setActive(-1, false);
          dom.rows.scrollTop = 0;
          showEmpty(null);
          if (page.total === 0) {
            if (path) showEmpty('folder', 'This folder is empty');
            else showEmpty('vault', 'This vault is empty', 'Files appear here after `gclone copy` or `gclone sync` on one of your devices.');
          }
        } else {
          view.entries = view.entries.concat(page.entries);
          view.total = page.total;
        }
        layout();
        renderCount();
        if (select && view.active < 0) {
          const at = view.entries.findIndex((e) => e.name === select);
          if (at >= 0) setActive(at, true);
        }
        offset += page.entries.length;
        if (offset >= page.total || page.entries.length === 0) break;
      }
      // What the list shows and what the summary says belong together (cheap: the replica).
      loadInfo(false);
    } catch (error) {
      if (mine === generation) failList(error);
    } finally {
      setBusy(false);
    }
  }

  async function loadSearch(q) {
    const mine = ++generation;
    Object.assign(view, { mode: 'search', q, error: false });
    renderCrumbs();
    setBusy(true);
    try {
      // Ordered by the server, by the rule it uses for folders.
      const found = await api('search', { q, ...order() });
      if (mine !== generation) return;
      view.entries = found.hits;
      view.entriesDir = '';
      view.total = found.hits.length;
      view.more = found.more;
      view.loaded = searchKey(q);
      dom.rows.scrollTop = 0;
      showEmpty(null);
      if (view.total === 0) showEmpty('search', 'Nothing found', `No file or folder name in the vault contains “${q}”.`);
      setActive(-1, false);
      layout();
      renderCount();
    } catch (error) {
      if (mine === generation) failList(error);
    } finally {
      setBusy(false);
    }
  }

  // ---- routing --------------------------------------------------------------------------------

  function route(force) {
    const target = where();
    const inSearchBox = document.activeElement === dom.search;
    if (target.search != null) {
      closeViewer();
      if (!inSearchBox || dom.search.value.trim() !== target.search) dom.search.value = target.search;
      if (force || view.loaded !== searchKey(target.search)) loadSearch(target.search);
      else renderCrumbs();
      if (!inSearchBox) dom.list.focus({ preventScroll: true });
      return;
    }
    const dir = target.file != null ? parentOf(target.file) : target.dir;
    // A file opened from the search results stays over them.
    const overSearch = target.file != null && view.mode === 'search' && view.loaded;
    if (!overSearch) {
      if (!inSearchBox) dom.search.value = '';
      if (force || view.loaded !== dirKey(dir)) {
        const from = view.mode === 'dir' && parentOf(view.path) === dir ? nameOf(view.path) : null;
        loadDir(dir, target.file != null ? nameOf(target.file) : from);
      } else {
        Object.assign(view, { mode: 'dir', path: dir });
        renderCrumbs();
      }
    }
    if (target.file != null) openViewer(target.file);
    else {
      closeViewer();
      if (!inSearchBox && !dom.info.contains(document.activeElement)) dom.list.focus({ preventScroll: true });
    }
  }

  function open(i) {
    const entry = view.entries[i];
    if (!entry) return;
    setActive(i, false);
    navigate(placeOf(entry), false);
  }

  function goUp() {
    if (view.mode === 'search') leaveSearch();
    else if (view.path) navigate({ dir: parentOf(view.path) }, false);
  }

  // ---- preview --------------------------------------------------------------------------------

  // `entry` with an id: a card that offers the download.
  function card(iconName, kind, title, text, entry, error) {
    return el('div', { class: error ? 'card error' : 'card' },
      icon(iconName, kind ? `t-${kind}` : ''),
      el('h2', { text: show(title) }),
      text ? prose(el('p'), text) : null,
      entry ? downloadLink(entry, 'btn', icon('download'), el('span', { text: 'Download' })) : null);
  }

  const failed = (error) => card('info', '', 'This file cannot be read', error.message, null, true);
  const kindCard = (entry, text) => card(ICONS[entry.kind] || 'file', entry.kind, entry.name, text, entry);

  // "Loading…", over whatever is on its way: a preview takes at least one trip to the store.
  function loading(name, size) {
    const what = size == null ? show(name) : `${show(name)} (${formatSize(size)})`;
    return el('div', { class: 'loading', role: 'status' },
      el('span', { class: 'spinner', 'aria-hidden': 'true' }),
      el('span', { class: 'loading-text', text: `Loading ${what}…` }));
  }

  // The first byte of the file, to learn what the store says before the browser is sent
  // there: an element or a download cannot show the server's reason.
  const probe = (entry) => (entry.size > 0
    ? request(fileUrl(entry.id), { headers: { Range: 'bytes=0-0' } }) : Promise.resolve());

  function downloadLink(entry, cls, ...children) {
    const node = el('a', { class: `${cls} dl`, href: fileUrl(entry.id, true), download: provider.downloadAttribute, title: 'Download this file' }, ...children);
    node.entry = entry;
    return node;
  }

  // A click on a download control: asked of the store first, so that a file it cannot
  // deliver is an error in the page, not a download that silently fails.
  async function download(control) {
    if (control.classList.contains('wait')) return;
    const mine = viewerGen;
    control.classList.add('wait');
    try {
      await probe(control.entry);
      const go = el('a', { href: control.getAttribute('href'), download: provider.downloadAttribute, hidden: true });
      document.body.append(go);
      go.click();
      go.remove();
    } catch (error) {
      if (mine === viewerGen) showFailure(failed(error));
    } finally {
      control.classList.remove('wait');
    }
  }

  // An error in place of the file: nothing to download, nothing to open.
  function showFailure(node) {
    $('viewer-download').hidden = true;
    $('viewer-open').hidden = true;
    dom.viewerBody.replaceChildren(node);
  }

  // Text of unknown encoding: a byte-order mark decides; else UTF-8 if the bytes are valid
  // UTF-8, else Windows-1252. `cut`: the bytes end inside the file — a sequence that the cut
  // split is dropped, not shown as a replacement character.
  function decodeText(buffer, cut) {
    const bytes = new Uint8Array(buffer);
    const bom = bytes.length >= 2 ? (bytes[0] << 8) | bytes[1] : 0;
    if (bom === 0xfffe) return new TextDecoder('utf-16le').decode(bytes, { stream: cut });
    if (bom === 0xfeff) return new TextDecoder('utf-16be').decode(bytes, { stream: cut });
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes, { stream: cut });
    } catch (_) {
      return new TextDecoder('windows-1252').decode(bytes);
    }
  }

  async function fillViewer(entry, mine) {
    const body = dom.viewerBody;
    const put = (...nodes) => { if (mine === viewerGen) body.replaceChildren(...nodes); };
    const fail = (error) => { if (mine === viewerGen) showFailure(failed(error)); };
    // Why an image, a video or a PDF did not show: the server's reason, or the browser's limits.
    const fallback = async () => {
      try {
        await probe(entry);
        put(kindCard(entry, 'This browser cannot show the file. Download it to open it.'));
      } catch (error) {
        fail(error);
      }
    };
    const url = fileUrl(entry.id);
    if (!PREVIEWS.has(entry.kind)) {
      put(kindCard(entry, `No preview for this kind of file (${formatSize(entry.size)}).`));
      return;
    }
    if (entry.size === 0) {
      put(kindCard(entry, 'This file is empty.'));
      return;
    }
    // The element loads under the note; the note goes when it has something to show.
    const wait = loading(entry.name, entry.size);
    const ready = () => wait.remove();
    if (entry.kind === 'image') {
      const image = el('img', { class: 'v-image', alt: show(entry.name), src: url });
      image.addEventListener('load', ready, { once: true });
      image.addEventListener('error', fallback, { once: true });
      put(wait, image);
    } else if (entry.kind === 'video' || entry.kind === 'audio') {
      const media = el(entry.kind, { class: `v-${entry.kind}`, controls: true, preload: 'metadata', src: url, 'aria-label': entry.name });
      media.addEventListener('loadedmetadata', ready, { once: true });
      media.addEventListener('error', fallback, { once: true });
      put(wait, media);
    } else if (entry.kind === 'pdf' && !provider.pdfInline) {
      // No frame for a PDF (a browser that shows only its first page in one; a viewer that
      // keeps PDFs out of its own tab): a tab of its own, which the viewer has no hold on.
      const box = kindCard(entry, 'A PDF opens in a tab of its own. That tab is not part of the viewer: close it when you are done.');
      box.insertBefore(el('a', { class: 'btn', href: url, target: '_blank', rel: 'noopener' },
        icon('open'), el('span', { text: 'Open' })), box.lastChild);
      put(box);
    } else if (entry.kind === 'pdf') {
      // A frame cannot say that it failed: ask for the first byte before it is filled.
      put(wait);
      try {
        await probe(entry);
        const frame = el('iframe', { class: 'v-frame', title: entry.name, src: url });
        frame.addEventListener('load', ready, { once: true });
        // A browser whose PDF viewer never reports "loaded" must not hide it for good.
        setTimeout(ready, 4000);
        put(wait, frame);
      } catch (error) {
        fail(error);
      }
    } else {
      put(wait);
      try {
        const res = await request(url, { headers: { Range: `bytes=0-${TEXT_PREVIEW - 1}` } });
        const cut = entry.size > TEXT_PREVIEW;
        const text = decodeText(await res.arrayBuffer(), cut);
        const pre = el('pre', { class: 'v-text', tabindex: '0', 'aria-label': `Contents of ${entry.name}` });
        if (cut) {
          pre.append(el('span', { class: 'v-note', text: `The first ${formatSize(TEXT_PREVIEW)} of ${formatSize(entry.size)}. Download the file to see all of it.` }));
        }
        pre.append(document.createTextNode(text));
        put(pre);
      } catch (error) {
        fail(error);
      }
    }
  }

  // The files of the list, for "previous" and "next".
  function neighbour(step) {
    if (!shown) return null;
    const files = view.entries.filter((e) => !e.dir);
    const at = files.findIndex((e) => pathOf(e) === shown.path);
    return at < 0 ? null : files[at + step] || null;
  }

  function renderViewerNav() {
    $('viewer-prev').disabled = !neighbour(-1);
    $('viewer-next').disabled = !neighbour(1);
  }

  // The preview is a modal dialog: while it is open, the page behind it is inert — out of
  // the tab order and out of reach of the keyboard.
  function setBehind(inert) {
    for (const node of document.querySelectorAll('body > :not(#viewer):not(.sprite)')) node.inert = inert;
  }

  async function openViewer(path) {
    const mine = ++viewerGen;
    const wasOpen = !dom.viewer.hidden;
    const name = nameOf(path);
    shown = { path, name };
    $('viewer-name').textContent = show(name);
    $('viewer-name').title = name;
    $('viewer-meta').textContent = '';
    $('viewer-download').hidden = true;
    $('viewer-open').hidden = true;
    dom.viewerBody.replaceChildren(loading(name));
    dom.viewer.hidden = false;
    setBehind(true);
    renderViewerNav();
    if (!wasOpen) $('viewer-close').focus({ preventScroll: true });
    try {
      // Always asked anew: the rows of the list may be those of another folder, or old —
      // and the answer carries the id the file is fetched by.
      const entry = await api('stat', { path });
      if (mine !== viewerGen) return;
      if (entry.dir) {
        navigate({ dir: path }, true);
        return;
      }
      $('viewer-meta').textContent = `${KINDS[entry.kind] || 'File'} · ${formatSize(entry.size)} · ${formatTime(entry.mtime_ms, false)}`;
      const save = $('viewer-download');
      save.entry = entry;
      save.setAttribute('href', fileUrl(entry.id, true));
      save.hidden = false;
      if (PREVIEWS.has(entry.kind) && entry.size > 0 && provider.openInTab(entry.kind)) {
        $('viewer-open').setAttribute('href', fileUrl(entry.id));
        $('viewer-open').hidden = false;
      }
      renderViewerNav();
      await fillViewer(entry, mine);
    } catch (error) {
      if (mine === viewerGen) showFailure(card('info', '', 'This file cannot be shown', error.message, null, true));
    }
  }

  function closeViewer() {
    if (dom.viewer.hidden) return;
    viewerGen += 1;
    shown = null;
    dom.viewer.hidden = true;
    setBehind(false);
    dom.viewerBody.replaceChildren(); // stops a video, drops a frame
  }

  // Back to the list the file was opened from; a file that was opened directly gives way to
  // its folder.
  function leaveViewer() {
    if (!shown) return;
    if (depth() > 0) history.back();
    else navigate(view.mode === 'search' && view.loaded ? { search: view.q } : { dir: parentOf(shown.path) }, true);
  }

  function step(by) {
    const next = neighbour(by);
    if (next) {
      const at = view.entries.indexOf(next);
      if (at >= 0) setActive(at, true);
      navigate({ file: pathOf(next) }, true);
    }
  }

  // ---- the vault ------------------------------------------------------------------------------

  // Also called without news from the server: "3 min ago" is true only when it is drawn.
  function renderInfo(info) {
    const renamed = (info.vault || 'Vault') !== vaultName;
    lastInfo = info;
    vaultName = info.vault || 'Vault';
    $('vault-name').textContent = vaultName;
    const changed = info.last_change_ms
      ? `${ago(info.last_change_ms)}${info.last_change_by ? ` by ${info.last_change_by}` : ''}` : null;
    dom.summary.textContent = `${count(info.files, 'file', 'files')} · ${formatSize(info.bytes)}${changed ? ` · last change ${changed}` : ''}`;
    const rows = [
      ['Vault', vaultName],
      ['Stored', info.backend === 'drive' ? 'on Google Drive, encrypted' : 'in a directory, encrypted'],
      ['Files', `${info.files.toLocaleString()} (${formatSize(info.bytes)})`],
      ['Last change', info.last_change_ms
        ? `${formatTime(info.last_change_ms, false)}${info.last_change_by ? ` by ${info.last_change_by}` : ''}` : 'none yet'],
      ['This device', info.device],
      ['Index', info.refresh.ok ? `refreshed ${ago(info.refresh.at_ms)}` : `not refreshed (tried ${ago(info.refresh.at_ms)})`],
      ['Viewer', `gclone ${info.version}, read-only`],
    ];
    const list = $('info-list');
    list.replaceChildren();
    for (const [term, value] of rows) list.append(el('dt', { text: term }), el('dd', { text: value }));
    if (renamed) renderCrumbs();
  }

  const redrawInfo = () => { if (lastInfo) renderInfo(lastInfo); };

  // `first`: the page has just started — the one time a failed refresh is announced here.
  // Later calls keep the summary in step with the list and say nothing when they fail.
  async function loadInfo(first) {
    try {
      const info = await api('info');
      renderInfo(info);
      if (first && !info.refresh.ok && info.refresh.note) notify(info.refresh.note, 'error', true);
    } catch (error) {
      if (first) notify(error.message, 'error', true);
    }
  }

  async function refresh() {
    const button = $('refresh');
    if (button.disabled) return;
    button.disabled = true;
    button.classList.add('spin');
    setBusy(true);
    try {
      const info = await api('refresh', null, { method: 'POST' });
      renderInfo(info);
      const state = info.refresh;
      if (!state.ok) notify(state.note || 'The index could not be refreshed.', 'error', true);
      else if (state.note) notify(state.note, 'error', true);
      else notify(state.applied > 0 ? `Refreshed: ${count(state.applied, 'new change set', 'new change sets')} from other devices.` : 'Up to date.');
      route(true);
    } catch (error) {
      notify(error.message, 'error', true);
    } finally {
      button.disabled = false;
      button.classList.remove('spin');
      setBusy(false);
    }
  }

  function toggleInfo(want) {
    const on = want == null ? dom.info.hidden : want;
    if (on) redrawInfo();
    dom.info.hidden = !on;
    dom.infoBtn.setAttribute('aria-expanded', String(on));
  }

  // ---- events ---------------------------------------------------------------------------------

  window.addEventListener('popstate', () => route());

  document.addEventListener('click', (event) => {
    if (!dom.info.hidden && !dom.info.contains(event.target) && !dom.infoBtn.contains(event.target)) toggleInfo(false);
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const anchor = event.target.closest('a');
    const row = event.target.closest('.row');
    if (anchor && anchor.classList.contains('dl')) {
      event.preventDefault();
      download(anchor);
    } else if (anchor && anchor.classList.contains('skip')) {
      event.preventDefault();
      dom.list.focus();
    } else if (row) {
      event.preventDefault();
      open(Number(row.dataset.i));
    } else if (anchor && anchor.place) {
      event.preventDefault();
      navigate(anchor.place, false);
    }
  });

  dom.crumbs.addEventListener('scroll', fadeCrumbs, { passive: true });
  dom.rows.addEventListener('scroll', schedulePaint, { passive: true });
  new ResizeObserver(() => paint(true)).observe(dom.rows);
  narrow.addEventListener('change', layout);

  for (const button of document.querySelectorAll('.head button')) {
    button.addEventListener('click', () => {
      const key = button.dataset.sort;
      // Names start ascending; sizes and times with the largest and the newest.
      sort = key === sort.key ? { key, desc: !sort.desc } : { key, desc: key !== 'name' };
      try { localStorage.setItem('gclone.sort', JSON.stringify(sort)); } catch (_) { /* not kept */ }
      renderSort();
      if (view.mode === 'search') loadSearch(view.q);
      else loadDir(view.path, null);
    });
  }

  dom.search.addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      const q = dom.search.value.trim();
      if (q) navigate({ search: q }, view.mode === 'search');
      else leaveSearch();
    }, 200);
  });

  $('brand').place = { dir: '' };
  $('refresh').addEventListener('click', refresh);
  dom.infoBtn.addEventListener('click', () => toggleInfo());
  $('notice-close').addEventListener('click', () => notify(null));
  $('viewer-close').addEventListener('click', leaveViewer);
  $('viewer-prev').addEventListener('click', () => step(-1));
  $('viewer-next').addEventListener('click', () => step(1));

  // The summary follows the clock and the vault while the page stays open.
  setInterval(() => {
    if (document.visibilityState === 'visible') loadInfo(false).then(redrawInfo);
  }, 60000);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') redrawInfo();
  });

  document.addEventListener('keydown', (event) => {
    document.documentElement.classList.add('kbd'); // the list's focus ring is for keyboard users
    if (event.metaKey || event.ctrlKey || event.altKey) return;
    const target = event.target;
    const key = event.key;
    if (key === 'Escape' && !dom.info.hidden) {
      toggleInfo(false);
      dom.infoBtn.focus();
      event.preventDefault();
      return;
    }
    if (!dom.viewer.hidden) {
      // Keys inside a player or the text belong to it.
      const own = target.closest && target.closest('video, audio, pre');
      if (key === 'Escape' || (key === 'Backspace' && !own)) leaveViewer();
      else if (key === 'ArrowLeft' && !own) step(-1);
      else if (key === 'ArrowRight' && !own) step(1);
      else return;
      event.preventDefault();
      return;
    }
    if (target === dom.search) {
      if (key === 'Escape') {
        leaveSearch();
        dom.list.focus({ preventScroll: true });
      } else if (key === 'ArrowDown' || key === 'Enter') {
        dom.list.focus({ preventScroll: true });
      } else return;
      event.preventDefault();
      return;
    }
    if (key === '/') {
      dom.search.focus();
      dom.search.select();
      event.preventDefault();
      return;
    }
    // Buttons and links keep their own keys.
    if (target.closest && target.closest('button, a, input, select, textarea') && target !== dom.list) return;
    const page = Math.max(1, Math.floor(dom.rows.clientHeight / rowHeight()) - 1);
    const moves = { ArrowDown: 1, ArrowUp: -1, PageDown: page, PageUp: -page };
    if (key in moves) setActive(Math.max(0, view.active + moves[key]), true);
    else if (key === 'Home') setActive(0, true);
    else if (key === 'End') setActive(view.entries.length - 1, true);
    else if (key === 'Enter') open(view.active);
    else if (key === 'Backspace') goUp();
    else if (key === 'Escape' && view.mode === 'search') leaveSearch();
    else return;
    event.preventDefault();
  });

  // ---- start ------------------------------------------------------------------------------------

  if (!provider.downloadAttribute) $('viewer-download').removeAttribute('download');
  renderSort();
  renderCrumbs();
  loadInfo(true);
  route(true);
})();
