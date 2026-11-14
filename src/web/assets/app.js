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
//
// The page is read-only, also where it shows the past (the time machine): earlier versions
// and deleted files can be looked at and saved, and the command that brings one back is
// shown to be copied — restoring is `gclone restore`, on a device.
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
  const KEPT_DAYS = 25; // how long replaced and deleted versions are kept (`gclone restore`)
  const HOUR = 3600 * 1000;
  const STEPS = KEPT_DAYS * 24; // positions of the time slider: one per hour, the last is now
  const narrow = window.matchMedia('(max-width: 719px)');

  const dom = {
    list: $('list'), rows: $('rows'), canvas: $('canvas'), empty: $('empty'),
    crumbs: $('crumbs'), search: $('search'), count: $('count'), summary: $('summary'),
    notice: $('notice'), noticeText: $('notice-text'), viewer: $('viewer'),
    viewerBody: $('viewer-body'), info: $('info'), infoBtn: $('info-btn'),
    time: $('time'), timeBtn: $('time-btn'), range: $('time-range'), when: $('time-when'),
    versions: $('versions'), versionsBtn: $('viewer-versions'), goneBtn: $('gone-btn'),
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
    live: 0, // of `entries`: those that are in the folder (or matches)
    deleted: 0, // rows of the "deleted from this folder" section
    noneDeleted: false, // that section was asked for, and nothing is kept
    gone: null, // the folder itself is deleted: { restore, then }
    absent: false, // the folder did not exist at the moment shown
  };
  let sort = { key: 'name', desc: false };
  let generation = 0; // of list requests: late answers are dropped
  let lastDir = ''; // where "clear the search" returns to
  let shown = null; // the file in the viewer: { path, name, v }
  let viewerGen = 0;
  let vaultName = 'Vault';
  let lastInfo = null; // the vault summary as last received
  let busy = 0;
  let searchTimer = 0;

  // The time machine. `shownAt`: the moment the page shows (ms), or null for now. It is part
  // of the place (below), so back, forward and reload keep it; nothing of it is stored.
  let shownAt = null;
  let showDeleted = false; // the "Show deleted" switch: this page's memory only
  let timeline = null; // the last `timeline` answer, and when it came
  let timelineGen = 0;
  let timeTimer = 0; // the slider settles before the list follows it
  let listLoads = 0; // list requests on their way
  let waitingAt; // a moment chosen meanwhile (`undefined`: none)
  let wantsFocus = false; // the bar was opened by hand before its slider could take the focus
  let leaving = null; // a folder shown in the past that is now shown as it is: it may be gone
  const versions = { open: false, path: null, data: null, gen: 0 };

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
  // A moment of the time machine: with its weekday in the bar, short where space is.
  const fullTime = new Intl.DateTimeFormat(undefined, { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  const dayTime = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
  const dayOnly = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short' });
  // Every time that comes out of an answer is shown through these two: the index is not
  // trusted to hold dates a browser can format (`Intl` throws on one it cannot).
  const LATEST = 8.64e15; // the last millisecond a Date can hold
  function formatTime(ms, short) {
    if (ms == null) return '';
    const date = new Date(ms);
    if (Number.isNaN(date.getTime())) return '';
    return (short ? dateOnly : dateTime).format(date);
  }
  // A time in a sentence, in one of the formats above.
  function say(format, ms) {
    const date = new Date(ms);
    return ms == null || Number.isNaN(date.getTime()) ? 'an unknown time' : format.format(date);
  }

  const count = (n, one, many) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
  // How long ago something was, in words. `past`: of a moment that is shown as the past —
  // "just now" would not be one.
  function ago(ms, past) {
    const s = Math.max(0, (Date.now() - ms) / 1000);
    if (s < 60) return past ? 'less than a minute ago' : 'just now';
    if (s < 3600) return `${Math.floor(s / 60)} min ago`;
    if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
    if (s < 30 * 86400) return count(Math.floor(s / 86400), 'day', 'days') + ' ago';
    return formatTime(ms, true);
  }
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
    .replace(/[\u0000-\u001f\u007f]/g, (c) => (c === '\u007f' ? '␡' : String.fromCharCode(0x2400 + c.charCodeAt(0))))
    .replace(/[؜‎‏‪-‮⁦-⁩]/g, '�');

  // A sentence with `commands` in it: text nodes and <code> elements, never markup.
  function prose(node, text) {
    node.replaceChildren(...String(text || '').split('`').map((part, i) => (
      i % 2 ? el('code', { text: part }) : document.createTextNode(part))));
    return node;
  }

  // A command to copy: to the clipboard, or — where the browser refuses — selected, for the
  // person to copy. `say`: where the outcome is announced.
  async function copy(text, node, say) {
    try {
      await navigator.clipboard.writeText(text);
      say('Copied.');
    } catch (_) {
      const range = document.createRange();
      range.selectNodeContents(node);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      say('The command is selected: copy it.');
    }
  }

  // ---- places ---------------------------------------------------------------------------------
  // Where the page is — { dir }, { file } (shown over its folder) or { search } — lives in
  // history.state: reload, back and forward work, and neither the address nor the title ever
  // carries a name from the vault into the browser's history.
  //
  // A place of the time machine has more, and only then: `at` (the moment shown, ms), `v`
  // (with `file`: the id of one version of it), `gone` (with `dir`: the folder is a deleted
  // one). A place of the present is what it always was.

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
    let place = { dir: '' };
    if (state && typeof state.search === 'string' && state.search.trim()) place = { search: state.search.trim() };
    else if (state && typeof state.file === 'string' && state.file) place = { file: state.file };
    else if (state && typeof state.dir === 'string') place = { dir: state.dir };
    if (state && Number.isSafeInteger(state.at) && state.at > 0 && state.at <= LATEST) place.at = state.at;
    if (place.file != null && state && typeof state.v === 'string' && /^[0-9a-f]{12}$/.test(state.v)) place.v = state.v;
    if (place.dir != null && state && state.gone === true) place.gone = true;
    return place;
  }

  const samePlace = (a, b) => a.dir === b.dir && a.file === b.file && a.search === b.search
    && a.at === b.at && a.v === b.v && a.gone === b.gone;
  // A place at the moment the page shows: folders, the path, a search and files carry it.
  const then = (place) => (shownAt ? { ...place, at: shownAt } : place);
  function placeOf(entry) {
    const path = pathOf(entry);
    // A deleted row leads to what is kept of it: the folder's deleted content, or the file's
    // last version.
    if (entry.deleted) return entry.dir ? { dir: path, gone: true } : { file: path, v: entry.v };
    return then(entry.dir ? { dir: path } : { file: path });
  }
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
    else navigate(then({ dir: lastDir }), true);
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
  // The moment shown, as a parameter of `list`, `stat`, `search` and `versions`.
  const atParam = (at) => (at ? { at: String(at) } : {});

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

  // What a row says about its entry beyond name, size and time — in words, never by colour
  // alone: what became of an entry of the past, or how a deleted entry went.
  function markOf(entry) {
    if (entry.deleted) {
      if (entry.dir) return entry.files == null ? 'deleted' : `deleted · ${entry.files.toLocaleString()}${entry.files_more ? '+' : ''} ${entry.files === 1 ? 'file' : 'files'}`;
      return entry.gone ? `deleted ${say(dayOnly, entry.gone.ms)} by ${entry.gone.by}` : 'deleted';
    }
    const since = { deleted: 'deleted since', changed: 'changed since' }[entry.since] || '';
    // An entry of the past that may have come later than the moment shown (`approx`).
    return [entry.approx ? '≈ may have come later' : '', since].filter(Boolean).join(' · ');
  }
  const APPROX = 'Nothing records when this came into the vault: it brought no upload of its own (a folder, an empty file, a restored file, a copy of bytes the vault already held). It is shown from the last moment its device is known to have been active before it, and may have come later than the moment shown.';

  function buildRow(i, height) {
    const entry = view.entries[i];
    const common = {
      role: 'row',
      id: `row-${i}`,
      'aria-rowindex': String(i + 2),
      'data-i': String(i),
    };
    if (entry.sep) {
      // What follows was deleted from this folder: one cell, no file.
      const row = el('div', { class: 'row sep', ...common },
        el('div', { class: 'c-sep', role: 'gridcell' }, icon('trash'),
          el('span', { text: `Deleted from this folder · kept for ${KEPT_DAYS} days` })));
      row.style.transform = `translateY(${i * height}px)`;
      return row;
    }
    const path = pathOf(entry);
    const mark = markOf(entry);
    const meta = entry.dir ? '' : `${formatSize(entry.size)} · ${formatTime(entry.mtime_ms, true)}`;
    const why = entry.approx ? APPROX : null;
    let sub = el('span', { class: 'sub', title: why, text: [mark, meta].filter(Boolean).join(' · ') });
    if (view.mode === 'search') {
      // The folder of a match is what tells two matches apart: when it does not fit, it is
      // its beginning that is cut (`.where`), and the row's tooltip has all of it.
      const parent = parentOf(path);
      const where = parent ? `in ${show(parent)}` : `in ${show(vaultName)}`;
      const rest = [narrow.matches && meta ? formatSize(entry.size) : '', mark].filter(Boolean).join(' · ');
      sub = el('span', { class: 'sub where', title: parent || vaultName },
        el('bdi', { text: rest ? `${where} · ${rest}` : where }));
    }
    // The kind in words, for those who do not see the icon — and that an entry is deleted.
    const deleted = entry.dir ? 'Deleted folder: ' : 'Deleted file: ';
    const said = entry.deleted ? deleted : `${KINDS[entry.kind] || 'File'}: `;
    const row = el('div', {
      class: `row${i === view.active ? ' active' : ''}${entry.deleted ? ' gone' : ''}`,
      'aria-selected': i === view.active ? 'true' : 'false',
      ...common,
    },
    el('div', { class: 'c-name', role: 'gridcell' },
      typeIcon(entry.kind),
      el('div', { class: 'names' },
        link(placeOf(entry), { class: 'name', tabindex: '-1', title: entry.name },
          el('span', { class: 'sr', text: said }), show(entry.name)),
        sub),
      mark ? el('span', { class: 'since', title: why, text: mark }) : null),
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

  // `step`: the direction of the move, to pass over the line between the two sections.
  function setActive(i, reveal, step) {
    const n = view.entries.length;
    let at = n === 0 || i === -1 ? -1 : Math.max(0, Math.min(n - 1, i));
    if (at >= 0 && view.entries[at].sep) {
      at += step < 0 ? -1 : 1;
      if (at < 0 || at >= n) at = view.active;
    }
    view.active = at;
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

  // `go`: a place the card leads to, as a button: { label, place }.
  function showEmpty(iconName, title, text, go) {
    dom.empty.hidden = !title;
    const button = $('empty-open');
    button.hidden = !(title && go);
    if (!title) return;
    $('empty-icon').firstElementChild.setAttribute('href', `#i-${iconName}`);
    $('empty-title').textContent = title;
    prose($('empty-text'), text);
    if (go) {
      button.textContent = go.label;
      button.place = go.place;
    }
  }

  function renderCrumbs() {
    const items = [];
    const crumb = (label, place, current, glyph) => el('li', null, current
      ? el('span', { 'aria-current': 'page', title: label }, glyph ? icon(glyph) : null, show(label))
      : link(place, { title: label, text: show(label) }));
    if (view.mode === 'search') {
      items.push(crumb(vaultName, then({ dir: '' }), false));
      items.push(crumb(`Search: “${view.q}”`, null, true));
    } else {
      const parts = view.path ? view.path.split('/') : [];
      items.push(crumb(vaultName, then({ dir: '' }), parts.length === 0));
      parts.forEach((part, i) => {
        const last = i === parts.length - 1;
        // A folder that was deleted says so in the path, in words for those who hear it.
        items.push(crumb(part, then({ dir: parts.slice(0, i + 1).join('/') }), last, last && view.gone ? 'trash' : null));
        if (last && view.gone) items[items.length - 1].firstElementChild.prepend(el('span', { class: 'sr', text: 'Deleted folder: ' }));
      });
    }
    dom.crumbs.replaceChildren(...items);
    // The end of the path is what matters: the list scrolls, and starts at its end.
    dom.crumbs.scrollLeft = dom.crumbs.scrollWidth;
    fadeCrumbs();
    renderGone();
  }

  // Where the path's beginning is scrolled out of view, it fades out instead of being cut.
  function fadeCrumbs() {
    dom.crumbs.classList.toggle('cut', dom.crumbs.scrollLeft > 0);
  }

  // The switch for the deleted section, and — for a folder that is itself deleted — what
  // brings it back and when it was last there.
  function renderGone() {
    const folder = view.mode === 'dir' && !shownAt;
    dom.goneBtn.hidden = !folder || !!view.gone;
    dom.goneBtn.setAttribute('aria-pressed', String(showDeleted));
    const note = $('gone-note');
    note.hidden = !(folder && view.gone);
    if (note.hidden) return;
    const { restore, was } = view.gone;
    const text = $('gone-text');
    if (restore) {
      text.replaceChildren('This folder was deleted. Its files are kept for a while: on a device, ',
        el('code', { class: 'cmd', id: 'gone-cmd', text: restore }), ' brings them back.');
    } else {
      prose(text, 'This folder was deleted. Its files are kept for a while: `gclone restore --list` on the folder above it shows what can be brought back.');
    }
    $('gone-copy').hidden = !restore;
    const see = $('gone-then');
    see.hidden = !was;
    if (was) see.textContent = `See it as it was on ${say(dayTime, was)}`;
  }

  function renderSort() {
    for (const key of ['name', 'size', 'mtime']) {
      const header = $(`h-${key}`);
      if (key === sort.key) header.setAttribute('aria-sort', sort.desc ? 'descending' : 'ascending');
      else header.removeAttribute('aria-sort');
    }
  }

  function renderCount() {
    const live = view.live;
    // The past says so here too, in words.
    const asOf = shownAt ? `As of ${formatTime(shownAt)} · ` : '';
    let text = '';
    if (view.error) text = '';
    else if (view.mode === 'search') {
      text = asOf + (view.more
        ? `The first ${count(live, 'match', 'matches')} — there are more: refine the search`
        : count(live, 'match', 'matches'));
    } else if (view.absent) text = `${asOf}this folder was not there`;
    else if (view.gone) text = count(view.total, 'deleted item', 'deleted items');
    else if (live < view.total) text = `${asOf}${live.toLocaleString()} of ${count(view.total, 'item', 'items')} loaded…`;
    else if (view.deleted) text = `${count(view.total + view.deleted, 'item', 'items')}, ${view.deleted.toLocaleString()} of them deleted`;
    // "Show deleted" is on and there is nothing to show: said, so that it is not taken for
    // a switch that does nothing.
    else if (view.noneDeleted) text = `${count(view.total, 'item', 'items')} · nothing deleted in the last ${KEPT_DAYS} days`;
    else text = asOf + count(view.total, 'item', 'items');
    dom.count.textContent = text;
  }

  // What a list holds depends on the moment shown and on the deleted section, too.
  const dirKey = (path) => `dir\n${path}\n${sort.key}\n${sort.desc}\n${shownAt || ''}\n${showDeleted}`;
  const searchKey = (q) => `search\n${q}\n${sort.key}\n${sort.desc}\n${shownAt || ''}`;
  const order = () => ({ sort: sort.key, order: sort.desc ? 'desc' : 'asc' });

  function failList(error) {
    Object.assign(view, { entries: [], total: 0, live: 0, more: false, error: true, loaded: null, deleted: 0, noneDeleted: false });
    layout();
    renderCount();
    showEmpty('info', 'This cannot be shown', error.message);
  }

  // A list request ended. One is on its way at a time while the slider moves: the moment
  // chosen last meanwhile is the one that is shown next.
  function listDone() {
    listLoads = Math.max(0, listLoads - 1);
    if (listLoads === 0 && waitingAt !== undefined) {
      const at = waitingAt;
      waitingAt = undefined;
      chooseTime(at);
    }
  }

  // The answer is for another moment than the one asked for: the window has moved on (or
  // this device's clock is ahead of the vault's). The page takes the moment it was given.
  // Returns the moment the list now shows, or `undefined` when the place became "now".
  function adopt(asked, given, key) {
    if (given < asked) {
      navigate(without(where(), 'at'), true);
      return undefined;
    }
    shownAt = given;
    view.loaded = key();
    navigate({ ...where(), at: given }, true);
    if (given - asked > 60 * 1000) notify(`The earliest moment that is kept is now ${say(dayTime, given)}.`);
    return given;
  }

  const without = (place, ...fields) => {
    const copy = { ...place };
    for (const field of fields) delete copy[field];
    return copy;
  };

  // The moment of the rows that are shown and how many lists were shown so far, on the list
  // itself: what a script that drives the page waits for. (Numbers; no name of the vault.)
  const shownList = (at) => {
    dom.list.dataset.at = at ? String(at) : 'now';
    dom.list.dataset.n = String(Number(dom.list.dataset.n || 0) + 1);
  };

  const deletedRow = (entry) => ({ ...entry, deleted: true });

  // A folder that is not there now, with what is kept of it: its deleted content. `false`:
  // there is no such folder, and nothing kept under the name.
  // The pages of `deleted` for a folder, one after the other, from `first` on (the first
  // page, when the caller has it). `take(page, offset)` gets each while the list is still
  // the one that asked (`mine`); `false` from it ends the reading.
  async function deletedPages(path, mine, take, first) {
    let offset = 0;
    for (let page = first; ; page = null) {
      page = page || await api('deleted', { path, ...order(), offset: String(offset), limit: String(PAGE) });
      if (mine !== generation || take(page, offset) === false) return;
      offset += page.entries.length;
      if (page.entries.length === 0 || offset >= page.total) return;
    }
  }

  async function loadGone(path, mine, key) {
    let found;
    try {
      found = await api('deleted', { path, ...order(), offset: '0', limit: String(PAGE) });
    } catch (_) {
      return false;
    }
    if (mine !== generation) return true;
    if (!found.gone) return false;
    await deletedPages(path, mine, (page, offset) => {
      if (offset > 0) {
        view.entries = view.entries.concat(page.entries.map(deletedRow));
        layout();
        return true;
      }
      Object.assign(view, {
        entries: page.entries.map(deletedRow),
        entriesDir: path,
        total: page.total,
        live: 0,
        deleted: page.total,
        loaded: key,
        gone: { restore: page.restore || null, was: page.as_it_was_ms || null },
      });
      shownList(null);
      setActive(-1, false);
      dom.rows.scrollTop = 0;
      showEmpty(null);
      layout();
      renderCount();
      renderCrumbs();
      return true;
    }, found);
    if (mine === generation && !shownAt) loadInfo(false);
    return true;
  }

  // The section after a folder's rows: what was deleted from it and is still kept.
  async function loadDeleted(path, mine) {
    await deletedPages(path, mine, (page, offset) => {
      if (page.total === 0 || page.entries.length === 0) return false;
      if (offset === 0) {
        view.entries = view.entries.concat([{ sep: true, name: '' }]);
        view.deleted = page.total;
        showEmpty(null);
      }
      view.entries = view.entries.concat(page.entries.map(deletedRow));
      layout();
      renderCount();
      return true;
    });
  }

  // `hint`: the place says that the folder is a deleted one — its kept content is asked for
  // first.
  async function loadDir(path, select, hint) {
    const mine = ++generation;
    let at = shownAt;
    const key = () => dirKey(path);
    Object.assign(view, { mode: 'dir', path, q: '', more: false, error: false, deleted: 0, noneDeleted: false, gone: null, absent: false });
    lastDir = path;
    renderCrumbs();
    setBusy(true);
    listLoads += 1;
    try {
      if (hint && !at && await loadGone(path, mine, key())) {
        // The place says so from here on: reload, back and forward ask for the kept content
        // first, and not for a folder that is not there.
        const place = where();
        if (mine === generation && view.gone && place.dir === path && !place.at && !place.gone) navigate({ ...place, gone: true }, true);
        return;
      }
      let offset = 0;
      for (;;) {
        let page;
        try {
          page = await api('list', { path, ...order(), offset: String(offset), limit: String(PAGE), ...atParam(at) });
        } catch (error) {
          // No such folder now: it may be one that was deleted and is still kept.
          if (offset === 0 && !at && !hint && mine === generation && await loadGone(path, mine, key())) return;
          throw error;
        }
        if (mine !== generation) return;
        if (offset === 0) {
          if (at && Number.isFinite(page.at) && page.at !== at) {
            at = adopt(at, page.at, key);
            if (at === undefined || mine !== generation) return;
          }
          view.entries = page.entries;
          view.entriesDir = path;
          view.total = page.total;
          view.live = page.entries.length;
          view.loaded = key();
          view.absent = !!page.absent;
          shownList(at);
          setActive(-1, false);
          dom.rows.scrollTop = 0;
          showEmpty(null);
          if (page.absent) {
            const nearest = typeof page.nearest === 'string' ? page.nearest : '';
            showEmpty('clock', `“${show(nameOf(path))}” was not there on ${say(dateTime, at)}`,
              'Move the slider to a moment at which it was there, or open a folder that was there then.',
              { label: `Open “${show(nearest ? nameOf(nearest) : vaultName)}”`, place: { dir: nearest, at } });
          } else if (page.total === 0 && !(showDeleted && !at)) {
            if (path) showEmpty('folder', at ? 'This folder was empty' : 'This folder is empty');
            else showEmpty('vault', at ? 'The vault was empty' : 'This vault is empty', at ? '' : 'Files appear here after `gclone copy` or `gclone sync` on one of your devices.');
          }
        } else {
          view.entries = view.entries.concat(page.entries);
          view.total = page.total;
          view.live = view.entries.length;
        }
        layout();
        renderCount();
        if (select && view.active < 0) {
          const found = view.entries.findIndex((e) => e.name === select);
          if (found >= 0) setActive(found, true);
        }
        offset += page.entries.length;
        if (offset >= page.total || page.entries.length === 0) break;
      }
      if (showDeleted && !at) {
        await loadDeleted(path, mine);
        if (mine !== generation) return;
        if (view.total === 0 && view.deleted === 0) {
          if (path) showEmpty('folder', 'This folder is empty', `Nothing was deleted from it in the last ${KEPT_DAYS} days either.`);
          else showEmpty('vault', 'This vault is empty', 'Files appear here after `gclone copy` or `gclone sync` on one of your devices.');
        } else if (view.deleted === 0) {
          view.noneDeleted = true;
          renderCount();
        }
      }
      // What the list shows and what the summary says belong together. Not in the past: the
      // summary describes the present and is hidden there, and on a large vault it is a scan
      // of every file — one per step of the slider would hold up the lists and the previews.
      if (!at) loadInfo(false);
    } catch (error) {
      if (mine === generation) failList(error);
    } finally {
      setBusy(false);
      listDone();
    }
  }

  async function loadSearch(q) {
    const mine = ++generation;
    let at = shownAt;
    const key = () => searchKey(q);
    Object.assign(view, { mode: 'search', q, error: false, deleted: 0, noneDeleted: false, gone: null, absent: false });
    renderCrumbs();
    setBusy(true);
    listLoads += 1;
    try {
      // Ordered by the server, by the rule it uses for folders.
      const found = await api('search', { q, ...order(), ...atParam(at) });
      if (mine !== generation) return;
      if (at && Number.isFinite(found.at) && found.at !== at) {
        at = adopt(at, found.at, key);
        if (at === undefined || mine !== generation) return;
      }
      view.entries = found.hits;
      view.entriesDir = '';
      view.total = found.hits.length;
      view.live = found.hits.length;
      shownList(at);
      view.more = found.more;
      view.loaded = key();
      dom.rows.scrollTop = 0;
      showEmpty(null);
      if (view.total === 0) {
        showEmpty('search', 'Nothing found', at
          ? `No file or folder name in the vault contained “${q}” on ${say(dateTime, at)}.`
          : `No file or folder name in the vault contains “${q}”.`);
      }
      setActive(-1, false);
      layout();
      renderCount();
    } catch (error) {
      if (mine === generation) failList(error);
    } finally {
      setBusy(false);
      listDone();
    }
  }

  // ---- the time machine -----------------------------------------------------------------------
  // The bar between the header and the path: a slider over the days that are kept, the
  // changes of the vault as stops, a date field. Choosing a moment changes the place (`at`),
  // and everything the page shows follows from the place.

  // The slider's position of a moment, and the moment of a position (`null`: now).
  const positionOf = (at) => (at && timeline
    ? Math.max(0, Math.min(STEPS - 1, STEPS - Math.round((timeline.now_ms - at) / HOUR))) : STEPS);
  const momentOf = (position) => (position >= STEPS || !timeline ? null
    : Math.max(timeline.from_ms, timeline.now_ms - (STEPS - position) * HOUR));
  const two = (n) => String(n).padStart(2, '0');
  // A moment as a `datetime-local` field holds it: this device's time, to the minute.
  const fieldValue = (ms) => {
    const d = new Date(ms);
    return `${d.getFullYear()}-${two(d.getMonth() + 1)}-${two(d.getDate())}T${two(d.getHours())}:${two(d.getMinutes())}`;
  };

  // The changes of the vault inside the window, by time: one stop per moment.
  function stops() {
    const out = [];
    for (const [ms, files, device, approx] of timeline ? timeline.moments : []) {
      const last = out[out.length - 1];
      if (last && last.ms === ms) {
        last.files += files;
        last.approx = last.approx && !!approx;
      } else out.push({ ms, files, device: timeline.devices[device] || 'a device', approx: !!approx });
    }
    return out;
  }
  const whatChanged = (stop) => {
    if (stop.approx) return `${stop.device}, ${count(stop.files, 'file', 'files')} added`;
    return stop.files ? `${stop.device}, ${count(stop.files, 'file', 'files')} replaced or removed` : `${stop.device}, folders changed`;
  };
  // A stop is the millisecond before a change: the vault as that change found it.
  function neighbours() {
    const all = stops();
    const from = shownAt || (timeline ? timeline.now_ms : 0);
    let earlier = null;
    let later = null;
    for (const stop of all) {
      if (stop.ms <= from) earlier = stop;
      else if (stop.ms - 1 > from && !later) later = stop;
    }
    return { earlier, later, here: shownAt ? all.find((stop) => stop.ms - 1 === shownAt) || null : null, any: all.length > 0 };
  }

  // `at`: the moment the bar shows — the place's, or the one under the moving slider.
  function renderTime(at, moving) {
    if (at === undefined) at = shownAt;
    const label = at ? `The vault as of ${say(fullTime, at)} (${ago(at, true)})` : 'Now';
    $('time-label').textContent = label;
    dom.range.setAttribute('aria-valuetext', at ? `${say(fullTime, at)} (${ago(at, true)})` : 'Now');
    $('time-now').hidden = !shownAt;
    $('time-close').hidden = !!shownAt;
    $('time-hint').hidden = !!at || !timeline;
    if (!moving) dom.range.value = String(positionOf(at));
    const step = $('time-step');
    const prev = $('time-prev');
    const next = $('time-next');
    if (!timeline) {
      prev.disabled = true;
      next.disabled = true;
      dom.range.disabled = true;
      dom.when.disabled = true;
      return;
    }
    dom.range.disabled = false;
    dom.when.disabled = false;
    $('time-from').textContent = say(dayOnly, timeline.from_ms);
    dom.when.min = fieldValue(timeline.from_ms);
    dom.when.max = fieldValue(timeline.now_ms);
    if (!moving || at) dom.when.value = fieldValue(at || timeline.now_ms);
    const { earlier, later, here, any } = neighbours();
    const name = (stop) => `${stop.approx ? '≈ ' : ''}${say(dayTime, stop.ms)} — ${whatChanged(stop)}`;
    prev.disabled = !earlier;
    next.disabled = !shownAt;
    const named = (button, text) => { button.title = text; button.setAttribute('aria-label', text); };
    named(prev, earlier ? `Earlier change: ${name(earlier)}` : 'Earlier change: none in the days that are kept');
    named(next, later ? `Later change: ${name(later)}` : 'Later change: none — back to now');
    if (moving) return;
    if (here) step.textContent = `just before${here.approx ? ' ≈' : ''}: ${whatChanged(here)}`;
    else if (shownAt) step.textContent = '';
    else if (!any) step.textContent = `Nothing was replaced, deleted or added in the last ${KEPT_DAYS} days.${provider.privateAddress ? ' If that cannot be, check this device’s clock.' : ''}`;
    else step.textContent = '';
    step.hidden = !step.textContent;
  }

  // The strip over the slider: how much changed when. Decoration: the stops say it in words.
  function drawStrip() {
    const strip = $('time-strip');
    if (!timeline) {
      strip.replaceChildren();
      return;
    }
    const bars = new Array(narrow.matches ? 48 : 96).fill(0);
    const span = Math.max(1, timeline.now_ms - timeline.from_ms);
    for (const [ms, files] of timeline.moments) {
      const at = Math.min(bars.length - 1, Math.max(0, Math.floor(((ms - timeline.from_ms) / span) * bars.length)));
      bars[at] += Math.max(1, files);
    }
    const most = Math.log1p(Math.max(1, ...bars));
    strip.replaceChildren(...bars.map((files) => {
      const bar = el('span');
      bar.style.height = files ? `${Math.round(4 + 22 * (Math.log1p(files) / most))}px` : '0';
      return bar;
    }));
  }

  async function loadTimeline() {
    const mine = ++timelineGen;
    const step = $('time-step');
    if (!timeline) {
      step.textContent = 'Reading the vault’s history…';
      step.hidden = false;
    }
    try {
      const found = await api('timeline');
      if (mine !== timelineGen) return;
      timeline = { ...found, fetched: Date.now() };
      drawStrip();
      renderTime();
      // The bar was opened by hand while the slider could not take the focus yet: now it can,
      // if the person has not gone elsewhere.
      if (wantsFocus && document.activeElement === dom.timeBtn && !dom.time.hidden) dom.range.focus({ preventScroll: true });
    } catch (error) {
      if (mine !== timelineGen) return;
      step.textContent = error.message;
      step.hidden = false;
    } finally {
      if (mine === timelineGen) wantsFocus = false;
    }
  }

  function openTime(focus) {
    dom.time.hidden = false;
    dom.timeBtn.setAttribute('aria-expanded', 'true');
    // Until the first timeline has come the slider is disabled, and cannot be focused.
    wantsFocus = focus && !timeline;
    if (!timeline || Date.now() - timeline.fetched > 5 * 60 * 1000) loadTimeline();
    renderTime();
    if (focus) dom.range.focus({ preventScroll: true });
    schedulePaint();
  }

  // Only at now: in the past the bar stays, so that the way back is always in sight.
  function closeTime() {
    if (shownAt) return;
    dom.time.hidden = true;
    dom.timeBtn.setAttribute('aria-expanded', 'false');
    dom.timeBtn.focus({ preventScroll: true });
    schedulePaint();
  }

  // The moment to show from here on: `null` is now. Entering the past is a step of the
  // browser's history, moving in it is not, and "back to now" is one again.
  function chooseTime(at) {
    clearTimeout(timeTimer);
    if (at != null && timeline && at >= timeline.now_ms) at = null;
    if (at != null && listLoads > 0) {
      waitingAt = at;
      // The list on its way is for a moment nobody waits for any more: it ends with its next
      // answer (not with its last page), and then this moment is asked for.
      generation += 1;
      renderTime(at, true);
      return;
    }
    waitingAt = undefined;
    const place = where();
    if ((place.at || null) === (at || null)) {
      renderTime();
      return;
    }
    const next = without(place, 'at', 'v', 'gone');
    if (at) next.at = at;
    // Back to now inside a folder: it may be one that was deleted since.
    else if (place.dir) leaving = place.dir;
    navigate(next, !!at && !!place.at);
  }

  // The words in the empty search field: the whole phrase where it fits; on a phone, where the
  // field is narrow, the short one (the field's label always says all of it).
  function saySearch() {
    const day = shownAt ? say(dayOnly, shownAt) : '';
    dom.search.placeholder = narrow.matches ? (day ? `Search ${day}` : 'Search')
      : day ? `Search the vault as of ${day}` : 'Search the vault';
  }

  // What follows from the place's moment, wherever the page is.
  function showMoment(at) {
    const was = shownAt;
    shownAt = at || null;
    document.documentElement.classList.toggle('past', !!shownAt);
    dom.summary.hidden = !!shownAt;
    saySearch();
    dom.search.setAttribute('aria-label', shownAt
      ? `Search file and folder names in the vault as of ${formatTime(shownAt)}` : 'Search file and folder names in the whole vault');
    dom.list.setAttribute('aria-label', shownAt ? `Files and folders as of ${formatTime(shownAt)}` : 'Files and folders');
    $('brand').place = then({ dir: '' });
    if (shownAt && dom.time.hidden) openTime(false);
    else if (!dom.time.hidden) renderTime();
    if (was !== shownAt) $('time-said').textContent = shownAt ? `Showing the vault as of ${say(fullTime, shownAt)}.` : 'Showing the vault as it is now.';
  }

  // ---- routing --------------------------------------------------------------------------------

  function route(force) {
    const target = where();
    // A folder that was shown in the past and is now shown as it is: its kept content is
    // asked for first, as for a place that says it is a deleted one.
    const left = leaving;
    leaving = null;
    showMoment(target.at);
    const active = document.activeElement;
    const inSearchBox = active === dom.search;
    // Focus stays where the person is working: the search box, the popover, the time bar.
    const stay = inSearchBox || dom.info.contains(active) || dom.time.contains(active) || active === dom.goneBtn;
    if (target.search != null) {
      closeViewer();
      if (!inSearchBox || dom.search.value.trim() !== target.search) dom.search.value = target.search;
      if (force || view.loaded !== searchKey(target.search)) loadSearch(target.search);
      else renderCrumbs();
      if (!stay) dom.list.focus({ preventScroll: true });
      return;
    }
    const dir = target.file != null ? parentOf(target.file) : target.dir;
    // A file opened from the search results stays over them.
    const overSearch = target.file != null && view.mode === 'search' && view.loaded === searchKey(view.q);
    if (!overSearch) {
      if (!inSearchBox) dom.search.value = '';
      if (force || view.loaded !== dirKey(dir)) {
        const from = view.mode === 'dir' && parentOf(view.path) === dir ? nameOf(view.path) : null;
        loadDir(dir, target.file != null ? nameOf(target.file) : from, !!target.gone || (left !== null && left === target.dir && !target.at));
      } else {
        Object.assign(view, { mode: 'dir', path: dir });
        renderCrumbs();
      }
    }
    if (target.file != null) openViewer(target);
    else {
      closeViewer();
      if (!stay) dom.list.focus({ preventScroll: true });
    }
  }

  function open(i) {
    const entry = view.entries[i];
    if (!entry || entry.sep) return;
    setActive(i, false);
    // A deleted file opens on its last version, with the list of its versions beside it.
    if (entry.deleted && !entry.dir) versions.open = true;
    navigate(placeOf(entry), false);
  }

  function goUp() {
    if (view.mode === 'search') leaveSearch();
    else if (view.path) navigate(then({ dir: parentOf(view.path) }), false);
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
    const files = view.entries.filter((e) => !e.dir && !e.sep);
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

  // What the preview says about the version it shows, next to the name.
  function setChip(text) {
    const chip = $('viewer-chip');
    chip.hidden = !text;
    chip.textContent = text || '';
    dom.viewer.classList.toggle('chipped', !!text); // where the bar is narrow, the chip is a line under it
  }

  // `place`: { file } — with `v`, one version of the file; with `at`, the version of then.
  async function openViewer(place) {
    const path = place.file;
    const mine = ++viewerGen;
    const wasOpen = !dom.viewer.hidden;
    const name = nameOf(path);
    shown = { path, name, v: place.v || null };
    $('viewer-name').textContent = show(name);
    $('viewer-name').title = name;
    $('viewer-meta').textContent = '';
    $('viewer-download').hidden = true;
    $('viewer-open').hidden = true;
    setChip(place.at && !place.v ? `as of ${say(dateTime, place.at)}` : '');
    dom.viewerBody.replaceChildren(loading(name));
    dom.viewer.hidden = false;
    setBehind(true);
    renderViewerNav();
    setVersions(versions.open, false);
    if (!wasOpen) $('viewer-close').focus({ preventScroll: true });
    try {
      // Always asked anew: the rows of the list may be those of another folder, or old —
      // and the answer carries the id the file is fetched by.
      const entry = await api('stat', place.v ? { path, v: place.v } : { path, ...atParam(place.at) });
      if (mine !== viewerGen) return;
      if (entry.dir) {
        navigate(then({ dir: path }), true);
        return;
      }
      // A version that is not what the file is now says so; the one of the moment shown
      // says which moment.
      if (place.v && entry.since) setChip('Earlier version');
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
    versions.gen += 1;
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
    else navigate(then(view.mode === 'search' && view.loaded ? { search: view.q } : { dir: parentOf(shown.path) }), true);
  }

  function step(by) {
    const next = neighbour(by);
    if (next) {
      const at = view.entries.indexOf(next);
      if (at >= 0) setActive(at, true);
      navigate(placeOf(next), true);
    }
  }

  // ---- versions -------------------------------------------------------------------------------
  // A panel inside the preview: the file as it is and every earlier version that is kept.
  // Choosing one shows it in the preview, by the same code as any file.

  function setVersions(on, focus) {
    versions.open = on;
    dom.versions.hidden = !on;
    dom.viewer.classList.toggle('sided', on);
    dom.versionsBtn.setAttribute('aria-expanded', String(on));
    if (on && shown) loadVersions(focus);
    else if (!on && focus) dom.versionsBtn.focus({ preventScroll: true });
  }

  async function loadVersions(focus) {
    const mine = ++versions.gen;
    const { path, name } = shown;
    $('versions-title').textContent = `Versions of ${show(name)}`;
    if (versions.path === path && versions.data) renderVersions(focus);
    else {
      versions.data = null;
      $('versions-note').textContent = 'Reading the versions…';
      $('versions-list').replaceChildren();
      $('versions-restore').hidden = true;
    }
    try {
      const data = await api('versions', { path, ...atParam(shownAt) });
      if (mine !== versions.gen || !shown || shown.path !== path) return;
      versions.path = path;
      versions.data = data;
      renderVersions(focus);
    } catch (error) {
      if (mine === versions.gen) $('versions-note').textContent = error.message;
    }
  }

  // The row of the list that the preview shows.
  const selectedVersion = (rows) => (shown.v ? rows.find((r) => r.v === shown.v)
    : rows.find((r) => (shownAt ? r.shown : r.current))) || null;

  function renderVersions(focus) {
    const data = versions.data;
    const rows = data.versions;
    const list = $('versions-list');
    const hadFocus = focus || list.contains(document.activeElement);
    const selected = selectedVersion(rows);
    const notes = [];
    if (data.deleted && rows.length && rows[0].why === 'deleted') notes.push(`Deleted ${say(dayTime, rows[0].until_ms)} by ${rows[0].by}.`);
    if (rows.length === 0) notes.push(`No version of this file is kept. Replaced and deleted versions are kept for ${KEPT_DAYS} days.`);
    else if (rows.every((r) => r.current)) notes.push(`No earlier versions are kept. Replaced and deleted versions are kept for ${KEPT_DAYS} days.`);
    if (data.more) notes.push('Only the newest versions are listed.');
    $('versions-note').textContent = notes.join(' ');
    $('versions-note').hidden = notes.length === 0;
    const estimate = 'Estimated: the index records when a version was replaced, not when it was written';
    list.replaceChildren(...rows.map((r) => {
      const written = r.written_ms
        ? `written ${r.written_approx ? '≈ ' : ''}${say(dayTime, r.written_ms)} by ${r.written_by}`
        : `written by ${r.written_by} before ${say(dayOnly, data.from_ms)}`;
      const button = el('button', { type: 'button', 'aria-current': r === selected ? 'true' : null },
        el('span', { class: 'v-when' },
          el('span', { text: r.current ? 'Current' : `until ${say(dateTime, r.until_ms)}` }),
          el('span', { class: 'v-size', text: formatSize(r.size) })),
        r.current ? null : el('span', { class: 'v-what', text: `${r.why === 'deleted' ? 'deleted' : 'replaced'} by ${r.by}` }),
        el('span', { class: 'v-what', title: r.written_ms && r.written_approx ? estimate : null, text: written }),
        shownAt && r.shown ? el('span', { class: 'v-what v-then', text: `as of ${say(dateTime, shownAt)}` }) : null);
      button.version = r;
      return el('li', null, button);
    }));
    const box = $('versions-restore');
    box.hidden = !(selected && !selected.current);
    if (!box.hidden) {
      const kept = say(dayOnly, selected.until_ms + KEPT_DAYS * 24 * HOUR);
      const cmd = $('versions-cmd');
      cmd.hidden = !selected.restore;
      $('versions-copy').hidden = !selected.restore;
      $('versions-said').textContent = '';
      if (selected.restore) {
        $('versions-how').textContent = `To bring this version back, on a device (it is kept until ${kept}):`;
        cmd.textContent = selected.restore;
      } else {
        prose($('versions-how'), `This file’s name cannot be put into a command line. \`gclone restore --list\` on its folder shows what can be brought back (kept until ${kept}).`);
      }
    }
    if (hadFocus) {
      const current = list.querySelector('[aria-current]') || list.querySelector('button') || $('versions-close');
      current.focus({ preventScroll: true });
    }
  }

  // The version a row of the panel stands for, as a place: replaces the one shown.
  function chooseVersion(r) {
    if (!shown) return;
    const file = { file: shown.path };
    // The file as it is now, or as it was at the moment shown, is the plain place.
    const plain = shownAt ? r.shown : r.current;
    navigate(then(plain ? file : { ...file, v: r.v }), true);
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
  // One request at a time: a call made while one is on its way waits for that answer.
  let infoOnItsWay = null;
  function loadInfo(first) {
    if (infoOnItsWay) return infoOnItsWay;
    infoOnItsWay = (async () => {
      try {
        const info = await api('info');
        renderInfo(info);
        if (first && !info.refresh.ok && info.refresh.note) notify(info.refresh.note, 'error', true);
      } catch (error) {
        if (first) notify(error.message, 'error', true);
      } finally {
        infoOnItsWay = null;
      }
    })();
    return infoOnItsWay;
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
      // The list again, at the moment it shows; the history may have grown as well.
      if (!dom.time.hidden) loadTimeline();
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
    const version = event.target.closest('#versions-list button');
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
    } else if (version) {
      chooseVersion(version.version);
    }
  });

  dom.crumbs.addEventListener('scroll', fadeCrumbs, { passive: true });
  dom.rows.addEventListener('scroll', schedulePaint, { passive: true });
  new ResizeObserver(() => paint(true)).observe(dom.rows);
  narrow.addEventListener('change', () => { layout(); drawStrip(); saySearch(); });
  saySearch();

  for (const button of document.querySelectorAll('.head button')) {
    button.addEventListener('click', () => {
      const key = button.dataset.sort;
      // Names start ascending; sizes and times with the largest and the newest.
      sort = key === sort.key ? { key, desc: !sort.desc } : { key, desc: key !== 'name' };
      try { localStorage.setItem('gclone.sort', JSON.stringify(sort)); } catch (_) { /* not kept */ }
      renderSort();
      if (view.mode === 'search') loadSearch(view.q);
      else loadDir(view.path, null, !!view.gone);
    });
  }

  dom.search.addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      const q = dom.search.value.trim();
      if (q) navigate(then({ search: q }), view.mode === 'search');
      else leaveSearch();
    }, 200);
  });

  $('refresh').addEventListener('click', refresh);
  dom.infoBtn.addEventListener('click', () => toggleInfo());
  $('notice-close').addEventListener('click', () => notify(null));
  $('viewer-close').addEventListener('click', leaveViewer);
  $('viewer-prev').addEventListener('click', () => step(-1));
  $('viewer-next').addEventListener('click', () => step(1));
  dom.versionsBtn.addEventListener('click', () => setVersions(!versions.open, true));
  $('versions-close').addEventListener('click', () => setVersions(false, true));
  $('versions-copy').addEventListener('click', () => copy($('versions-cmd').textContent, $('versions-cmd'), (text) => { $('versions-said').textContent = text; }));
  $('empty-open').addEventListener('click', (event) => { if (event.currentTarget.place) navigate(event.currentTarget.place, false); });

  // The time machine's controls. In the past the bar cannot be closed: its button leads to it.
  dom.timeBtn.addEventListener('click', () => {
    if (dom.time.hidden) openTime(true);
    else if (shownAt) dom.range.focus({ preventScroll: true });
    else closeTime();
  });
  $('time-close').addEventListener('click', closeTime);
  $('time-now').addEventListener('click', () => {
    chooseTime(null);
    dom.list.focus({ preventScroll: true });
  });
  // The label follows the slider at once; the list follows when the slider rests.
  dom.range.addEventListener('input', () => {
    const at = momentOf(Number(dom.range.value));
    renderTime(at, true);
    clearTimeout(timeTimer);
    timeTimer = setTimeout(() => chooseTime(at), 150);
  });
  dom.range.addEventListener('change', () => chooseTime(momentOf(Number(dom.range.value))));
  dom.range.addEventListener('keydown', (event) => {
    // A day at a time; the arrow keys (an hour), Home and End are the slider's own.
    const days = { PageUp: 1, PageDown: -1 }[event.key];
    if (!days) return;
    event.preventDefault();
    dom.range.value = String(Math.max(0, Math.min(STEPS, Number(dom.range.value) + days * 24)));
    dom.range.dispatchEvent(new Event('input', { bubbles: true }));
  });
  $('time-prev').addEventListener('click', () => {
    const { earlier } = neighbours();
    if (earlier) chooseTime(earlier.ms - 1);
  });
  $('time-next').addEventListener('click', () => {
    const { later } = neighbours();
    chooseTime(later ? later.ms - 1 : null);
    if (!later) dom.list.focus({ preventScroll: true });
  });
  dom.when.addEventListener('change', () => {
    const at = new Date(dom.when.value).getTime();
    if (!timeline || !Number.isFinite(at)) return;
    chooseTime(Math.max(timeline.from_ms, at));
  });

  // What was deleted from the folder shown: a section after its rows.
  dom.goneBtn.addEventListener('click', () => {
    showDeleted = !showDeleted;
    renderGone();
    if (view.mode === 'dir') loadDir(view.path, null, false);
  });
  $('gone-copy').addEventListener('click', () => {
    const cmd = $('gone-cmd');
    if (cmd) copy(cmd.textContent, cmd, (text) => notify(text));
  });
  $('gone-then').addEventListener('click', () => {
    if (view.gone && view.gone.was) navigate({ dir: view.path, at: view.gone.was }, false);
  });

  // The summary follows the clock and the vault while the page stays open.
  setInterval(() => {
    if (document.visibilityState !== 'visible') return;
    // In the past the summary is not shown: only its clock moves on.
    if (shownAt) redrawInfo();
    else loadInfo(false).then(redrawInfo);
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
      // Keys inside a player, the text or the versions belong to them.
      const own = target.closest && target.closest('video, audio, pre, #versions');
      const inList = target.closest && target.closest('#versions-list');
      // Escape closes the versions first, then the preview.
      if (key === 'Escape' && versions.open) setVersions(false, true);
      else if (key === 'Escape' || (key === 'Backspace' && !own)) leaveViewer();
      else if (key === 'ArrowLeft' && !own) step(-1);
      else if (key === 'ArrowRight' && !own) step(1);
      else if ((key === 'ArrowDown' || key === 'ArrowUp') && inList) {
        const buttons = [...$('versions-list').querySelectorAll('button')];
        const next = buttons[buttons.indexOf(target.closest('button')) + (key === 'ArrowDown' ? 1 : -1)];
        if (next) next.focus();
      } else return;
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
    // Buttons, links and fields keep their own keys — the slider and the date field too.
    const control = target.closest && target.closest('button, a, input, select, textarea') && target !== dom.list;
    if (key === '/' && !(control && target.closest('input, textarea'))) {
      dom.search.focus();
      dom.search.select();
      event.preventDefault();
      return;
    }
    if (control) return;
    const page = Math.max(1, Math.floor(dom.rows.clientHeight / rowHeight()) - 1);
    const moves = { ArrowDown: 1, ArrowUp: -1, PageDown: page, PageUp: -page };
    if (key in moves) setActive(Math.max(0, view.active + moves[key]), true, moves[key]);
    else if (key === 'Home') setActive(0, true, 1);
    else if (key === 'End') setActive(view.entries.length - 1, true, -1);
    else if (key === 'Enter') open(view.active);
    else if (key === 'Backspace') goUp();
    else if (key === 'Escape' && view.mode === 'search') leaveSearch();
    else return;
    event.preventDefault();
  });

  // ---- start ------------------------------------------------------------------------------------

  if (!provider.downloadAttribute) $('viewer-download').removeAttribute('download');
  $('time-hint').textContent = `Kept for ${KEPT_DAYS} days. Changes and deletions are placed exactly. When a new file first appeared is estimated from its upload (≈); what came without one — a folder, an empty file, a restored file, a copy — is shown from the last its device was seen before, and marked.`;
  renderSort();
  renderCrumbs();
  loadInfo(true);
  route(true);
})();
