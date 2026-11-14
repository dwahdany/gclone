// The demo vault of the README's screenshots: a small, believable personal folder tree with
// invented content. Everything is made here — the pictures and the video are drawn by this
// file, the sound is synthesised — so that nothing of anybody's disk can end up in an image.
//
//   node worker/test/e2e/readme/content.mjs <directory>
//
// Needs `ffmpeg` on PATH (JPEG, H.264/AAC and MP3 encoding): `nix-shell -p ffmpeg nodejs`,
// or `brew install ffmpeg`. Deterministic but for what the encoders do.
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';

// --- drawing -------------------------------------------------------------------------------

const hash = (n) => {
  let x = Math.imul(n ^ 0x9e3779b9, 0x85ebca6b);
  x ^= x >>> 13; x = Math.imul(x, 0xc2b2ae35); x ^= x >>> 16;
  return (x >>> 0) / 4294967296;
};
const smooth = (t) => t * t * (3 - 2 * t);
const mix = (a, b, t) => a + (b - a) * t;
const mix3 = (a, b, t) => [mix(a[0], b[0], t), mix(a[1], b[1], t), mix(a[2], b[2], t)];
const clamp01 = (t) => (t < 0 ? 0 : t > 1 ? 1 : t);

/** Value noise in one dimension, and a few octaves of it (about -1 … 1). */
function noise1(x, seed) {
  const i = Math.floor(x);
  const t = smooth(x - i);
  return mix(hash(i + seed * 7919), hash(i + 1 + seed * 7919), t) * 2 - 1;
}
function fbm1(x, seed, octaves) {
  let sum = 0;
  let amp = 0.5;
  for (let o = 0; o < octaves; o += 1) {
    sum += noise1(x, seed + o * 31) * amp;
    x *= 2.03;
    amp *= 0.5;
  }
  return sum;
}
/** The same in two dimensions (0 … 1). */
function noise2(x, y, seed) {
  const ix = Math.floor(x);
  const iy = Math.floor(y);
  const tx = smooth(x - ix);
  const ty = smooth(y - iy);
  const at = (a, b) => hash(Math.imul(a, 73856093) ^ Math.imul(b, 19349663) ^ Math.imul(seed, 83492791));
  return mix(mix(at(ix, iy), at(ix + 1, iy), tx), mix(at(ix, iy + 1), at(ix + 1, iy + 1), tx), ty);
}
function fbm2(x, y, seed, octaves) {
  let sum = 0;
  let amp = 0.5;
  for (let o = 0; o < octaves; o += 1) {
    sum += noise2(x, y, seed + o * 17) * amp;
    x *= 2.02;
    y *= 2.02;
    amp *= 0.5;
  }
  return sum;
}

/** The colour at `t` (0 … 1) of a list of `[position, [r, g, b]]` stops. */
function gradient(stops, t) {
  if (t <= stops[0][0]) return stops[0][1];
  for (let i = 1; i < stops.length; i += 1) {
    if (t <= stops[i][0]) return mix3(stops[i - 1][1], stops[i][1], smooth((t - stops[i - 1][0]) / (stops[i][0] - stops[i - 1][0])));
  }
  return stops[stops.length - 1][1];
}

/**
 * A landscape of `width` x `height` as RGB bytes: a sky (gradient, sun, clouds, stars, an
 * aurora), ridges one behind the other, and water that mirrors them.
 *
 *   sky       [[position, rgb], …] from the top (0) to the horizon (1)
 *   horizon   where the sky's gradient ends, as a part of the height
 *   sun       { x, y, radius, rgb, glow } in parts of the width and the height
 *   clouds    { amount, rgb, scale, drift }
 *   stars     how many of a thousand pixels are one
 *   aurora    { rgb, high, top, strength, phase }
 *   ridges    { count, far, near, from, to, height, rough }: colours and base lines, far to near
 *   water     { level, tint, phase, stretch }: everything below `level` mirrors what is above it
 */
export function landscape(width, height, scene) {
  const seed = scene.seed || 1;
  const out = Buffer.alloc(width * height * 3);
  const ridges = scene.ridges;
  const lines = [];
  for (let i = 0; i < ridges.count; i += 1) {
    const depth = ridges.count === 1 ? 1 : i / (ridges.count - 1); // 0 far … 1 near
    const base = mix(ridges.from, ridges.to, depth) * height;
    const reach = ridges.height * height * mix(0.75, 1.15, depth);
    const scale = mix(2.2, 3.4, depth) * (ridges.rough || 1);
    const line = new Float32Array(width);
    for (let x = 0; x < width; x += 1) {
      const u = x / width;
      line[x] = base - (fbm1(u * scale + i * 11.3, seed + i * 101, 6) * 0.5 + 0.35) * reach;
    }
    lines.push({ line, colour: mix3(ridges.far, ridges.near, Math.pow(depth, 0.85)), depth });
  }
  const level = scene.water ? Math.round(scene.water.level * height) : height;
  const horizon = (scene.horizon || 0.7) * height;
  const sun = scene.sun;
  const clouds = scene.clouds;
  const aurora = scene.aurora;
  // An aurora is three curtains; where each hangs and how bright it is depends on the column alone.
  const curtains = [];
  for (let band = 0; aurora && band < 3; band += 1) {
    const centre = new Float32Array(width);
    const bright = new Float32Array(width);
    const phase = aurora.phase || 0;
    for (let x = 0; x < width; x += 1) {
      const u = x / width;
      centre[x] = (aurora.top + band * 0.08 + Math.sin(u * 4.4 + band * 1.9) * 0.05 + fbm1(u * 2.4 + band * 5 + phase, seed + 40 + band, 3) * 0.3) * height;
      const streak = 0.5 + 0.5 * (fbm1(u * 34 + band * 9 + phase * 3, seed + 60 + band, 3) + 0.5);
      const patch = clamp01(0.55 + fbm1(u * 3.1 + band * 13 + phase, seed + 80 + band, 2) * 1.5);
      bright[x] = streak * patch * (1 - band * 0.2) * aurora.strength;
    }
    curtains.push({ centre, bright, reach: height * (0.11 + band * 0.03) });
  }
  for (let y = 0; y < level; y += 1) {
    const sky = gradient(scene.sky, clamp01(y / horizon));
    for (let x = 0; x < width; x += 1) {
      let colour = null;
      for (let i = lines.length - 1; i >= 0; i -= 1) {
        const top = lines[i].line[x];
        if (y >= top) {
          // Mist gathers at the foot of a ridge: towards the next one's colour of the sky.
          const fall = clamp01((y - top) / (height * 0.22));
          colour = mix3(lines[i].colour, sky, fall * mix(0.5, 0.12, lines[i].depth));
          break;
        }
      }
      if (!colour) {
        let [r, g, b] = sky;
        const u = x / width;
        const v = y / height;
        if (scene.stars) {
          const star = hash(x * 7919 + y * 104729 + seed);
          if (star > 1 - scene.stars / 1000) {
            const bright = 90 + 165 * hash(x + y * 31 + seed * 3);
            const fade = clamp01(1.4 - (y / horizon) * 1.3);
            r += bright * fade; g += bright * fade; b += bright * fade;
          }
        }
        if (aurora) {
          let glow = 0;
          for (const curtain of curtains) {
            const d = (y - curtain.centre[x]) / curtain.reach;
            // Sharp below, long upwards.
            glow += (d > 0 ? Math.exp(-d * d * 9) : Math.exp(-d * d * 1.1)) * curtain.bright[x];
          }
          const tone = mix3(aurora.rgb, aurora.high || aurora.rgb, clamp01(1 - v / aurora.top * 0.9));
          r += tone[0] * glow; g += tone[1] * glow; b += tone[2] * glow;
        }
        if (sun) {
          const dx = (u - sun.x) * width;
          const dy = (v - sun.y) * height;
          const d = Math.sqrt(dx * dx + dy * dy) / (sun.radius * height);
          const disc = clamp01((1 - d) * 12);
          const halo = Math.exp(-d * 0.55) * sun.glow;
          r = mix(r + sun.rgb[0] * halo, sun.rgb[0], disc);
          g = mix(g + sun.rgb[1] * halo, sun.rgb[1], disc);
          b = mix(b + sun.rgb[2] * halo, sun.rgb[2], disc);
        }
        if (clouds) {
          const n = fbm2(u * clouds.scale * (width / height) + (clouds.drift || 0), v * clouds.scale * 2.6, seed + 200, 5);
          const cover = smooth(clamp01((n - (1 - clouds.amount) * 0.62) * 3.2)) * clamp01(1.25 - (y / horizon) * 0.55);
          r = mix(r, clouds.rgb[0], cover * 0.85);
          g = mix(g, clouds.rgb[1], cover * 0.85);
          b = mix(b, clouds.rgb[2], cover * 0.85);
        }
        colour = [r, g, b];
      }
      const at = (y * width + x) * 3;
      const grain = (hash(at + seed * 13) - 0.5) * 9;
      out[at] = Math.max(0, Math.min(255, colour[0] + grain));
      out[at + 1] = Math.max(0, Math.min(255, colour[1] + grain));
      out[at + 2] = Math.max(0, Math.min(255, colour[2] + grain));
    }
  }
  if (scene.water) {
    const { tint, phase = 0 } = scene.water;
    for (let y = level; y < height; y += 1) {
      const down = (y - level) / (height - level); // 0 at the shore … 1 at the lower edge
      const from = level - 1 - Math.floor((y - level) * (scene.water.stretch || 1.25));
      const ripple = Math.sin(y * 0.9 / (0.35 + down * 2.2) + phase) * (1 + down * 7) + fbm1(y * 0.21 + phase, seed + 300, 2) * (2 + down * 10);
      for (let x = 0; x < width; x += 1) {
        const sx = Math.max(0, Math.min(width - 1, Math.round(x + ripple * (width / 1600))));
        const sy = Math.max(0, from);
        const src = (sy * width + sx) * 3;
        const at = (y * width + x) * 3;
        const keep = 0.78 - down * 0.28;
        out[at] = mix(tint[0], out[src], keep);
        out[at + 1] = mix(tint[1], out[src + 1], keep);
        out[at + 2] = mix(tint[2], out[src + 2], keep);
      }
    }
  }
  return out;
}

const SCENES = {
  dusk: {
    seed: 3, horizon: 0.72,
    sky: [[0, [38, 44, 92]], [0.45, [150, 84, 128]], [0.78, [246, 148, 96]], [1, [255, 208, 138]]],
    sun: { x: 0.68, y: 0.5, radius: 0.034, rgb: [255, 236, 190], glow: 0.55 },
    clouds: { amount: 0.42, rgb: [255, 170, 140], scale: 1.6 },
    ridges: { count: 6, far: [196, 122, 132], near: [28, 22, 48], from: 0.6, to: 1.02, height: 0.2 },
  },
  morning: {
    seed: 11, horizon: 0.7,
    sky: [[0, [96, 150, 214]], [0.6, [176, 208, 236]], [1, [244, 236, 220]]],
    sun: { x: 0.24, y: 0.3, radius: 0.026, rgb: [255, 252, 236], glow: 0.35 },
    clouds: { amount: 0.5, rgb: [255, 255, 255], scale: 1.3 },
    ridges: { count: 7, far: [168, 196, 214], near: [22, 58, 60], from: 0.52, to: 1.04, height: 0.19 },
  },
  aurora: {
    seed: 29, horizon: 0.74, stars: 1.6,
    sky: [[0, [4, 8, 26]], [0.6, [10, 26, 52]], [1, [22, 52, 70]]],
    aurora: { rgb: [60, 235, 150], high: [150, 90, 220], top: 0.22, strength: 0.85, phase: 0 },
    ridges: { count: 4, far: [20, 40, 60], near: [3, 6, 12], from: 0.62, to: 0.76, height: 0.16 },
    water: { level: 0.72, tint: [4, 12, 22], stretch: 2.3 },
  },
  fjord: {
    seed: 47, horizon: 0.62,
    sky: [[0, [70, 128, 200]], [0.55, [150, 196, 232]], [1, [226, 236, 240]]],
    clouds: { amount: 0.55, rgb: [255, 255, 255], scale: 1.5 },
    ridges: { count: 5, far: [150, 178, 204], near: [34, 62, 74], from: 0.5, to: 0.66, height: 0.3, rough: 0.8 },
    water: { level: 0.64, tint: [40, 78, 104] },
  },
  dunes: {
    seed: 61, horizon: 0.66,
    sky: [[0, [84, 150, 206]], [0.7, [186, 214, 226]], [1, [246, 226, 190]]],
    sun: { x: 0.8, y: 0.2, radius: 0.03, rgb: [255, 250, 226], glow: 0.3 },
    ridges: { count: 6, far: [236, 200, 150], near: [150, 84, 40], from: 0.6, to: 1.05, height: 0.2, rough: 0.7 },
  },
  hills: {
    seed: 83, horizon: 0.68,
    sky: [[0, [120, 170, 220]], [0.7, [200, 224, 236]], [1, [240, 244, 232]]],
    clouds: { amount: 0.62, rgb: [252, 252, 250], scale: 1.9 },
    ridges: { count: 7, far: [170, 204, 196], near: [30, 70, 34], from: 0.52, to: 1.05, height: 0.22, rough: 1 },
  },
  ember: {
    seed: 97, horizon: 0.7,
    sky: [[0, [30, 30, 70]], [0.5, [120, 60, 110]], [0.82, [236, 110, 80]], [1, [255, 190, 110]]],
    sun: { x: 0.36, y: 0.57, radius: 0.04, rgb: [255, 226, 170], glow: 0.6 },
    clouds: { amount: 0.36, rgb: [250, 140, 120], scale: 1.4 },
    ridges: { count: 4, far: [150, 80, 110], near: [24, 16, 36], from: 0.62, to: 0.72, height: 0.2 },
    water: { level: 0.7, tint: [60, 30, 50] },
  },
};

// Variations: the same weather on other ground.
Object.assign(SCENES, {
  midnight: { ...SCENES.ember, seed: 131, sun: { ...SCENES.ember.sun, x: 0.62, y: 0.6 }, clouds: { ...SCENES.ember.clouds, amount: 0.3 } },
  trail: { ...SCENES.fjord, seed: 59, sun: { x: 0.78, y: 0.16, radius: 0.028, rgb: [255, 252, 236], glow: 0.3 }, clouds: { ...SCENES.fjord.clouds, amount: 0.4 } },
  rain: {
    ...SCENES.morning, seed: 71, sun: undefined,
    sky: [[0, [92, 104, 122]], [0.6, [150, 160, 172]], [1, [206, 208, 206]]],
    clouds: { amount: 0.7, rgb: [226, 228, 230], scale: 1.7 },
    ridges: { ...SCENES.morning.ridges, far: [150, 162, 170], near: [26, 40, 44] },
  },
  lake: { ...SCENES.aurora, seed: 37, aurora: { ...SCENES.aurora.aurora, top: 0.2, strength: 0.9 }, ridges: { ...SCENES.aurora.ridges, from: 0.66, to: 0.76, height: 0.1 }, water: { ...SCENES.aurora.water, level: 0.74, stretch: 2.6 } },
  wallpaper: { ...SCENES.dusk, seed: 19, sun: { ...SCENES.dusk.sun, x: 0.3 } },
});

function ffmpeg(args, input) {
  const out = spawnSync('ffmpeg', ['-hide_banner', '-loglevel', 'error', '-y', ...args], { input, maxBuffer: 1 << 28 });
  if (out.error) throw new Error(`ffmpeg is needed for the demo content and did not start (${out.error.message}): nix-shell -p ffmpeg, or brew install ffmpeg`);
  if (out.status !== 0) throw new Error(`ffmpeg ${args.join(' ')} failed:\n${out.stderr}`);
}

const PLAIN = ['-map_metadata', '-1', '-fflags', '+bitexact'];

function photo(file, scene, width = 3000, height = 2000) {
  ffmpeg(['-f', 'rawvideo', '-pix_fmt', 'rgb24', '-s', `${width}x${height}`, '-i', '-', '-frames:v', '1', '-q:v', '1', ...PLAIN, file], landscape(width, height, SCENES[scene]));
}

/** `seconds` of a scene that changes with `at(t)` (t from 0 to 1), with the sound of wind. */
async function film(file, seconds, width, height, at, rate = 24) {
  const child = spawn('ffmpeg', ['-hide_banner', '-loglevel', 'error', '-y',
    '-f', 'rawvideo', '-pix_fmt', 'rgb24', '-s', `${width}x${height}`, '-r', String(rate), '-i', '-',
    '-f', 'lavfi', '-i', `anoisesrc=color=pink:amplitude=0.25:seed=7:duration=${seconds},lowpass=f=500,tremolo=f=0.3:d=0.7`,
    '-c:v', 'libx264', '-preset', 'slow', '-crf', '21', '-pix_fmt', 'yuv420p', '-c:a', 'aac', '-b:a', '96k',
    '-shortest', '-movflags', '+faststart', ...PLAIN, file], { stdio: ['pipe', 'inherit', 'inherit'] });
  const done = new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`ffmpeg exited ${code} writing ${file}`))));
  });
  const frames = seconds * rate;
  for (let i = 0; i < frames; i += 1) {
    const frame = landscape(width, height, at(i / (frames - 1)));
    if (!child.stdin.write(frame)) await new Promise((resolve) => child.stdin.once('drain', resolve));
  }
  child.stdin.end();
  await done;
}

/** A few notes held together, `seconds` long: MP3, or AAC in an .m4a. */
function tune(file, seconds, notes, wobble) {
  const voices = notes.map((f, i) => `${(0.5 / notes.length).toFixed(3)}*sin(2*PI*${f}*t)*(0.6+0.4*sin(2*PI*${(0.11 + i * 0.07).toFixed(2)}*t))`).join('+');
  ffmpeg(['-f', 'lavfi', '-i', `aevalsrc=${voices}:d=${seconds}:s=44100`, '-af', `tremolo=f=${wobble}:d=0.4,afade=t=in:d=1.5,afade=t=out:st=${seconds - 3}:d=3`,
    '-ac', '2', ...(file.endsWith('.m4a') ? ['-c:a', 'aac', '-b:a', '128k'] : ['-c:a', 'libmp3lame', '-b:a', '192k']), ...PLAIN, file]);
}

// --- documents -----------------------------------------------------------------------------

/** A PDF of A4 pages: `pages` is a list of pages, a page a list of `[size, text]` (size 0: a rule; bold from 15 up). */
export function pdf(pages) {
  const escape = (text) => text.replace(/[()\\]/g, '\\$&');
  const objects = ['<< /Type /Catalog /Pages 2 0 R >>', null,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>'];
  const kids = [];
  for (const lines of pages) {
    let y = 780;
    let stream = '';
    for (const [size, text] of lines) {
      if (size === 0) {
        y -= 6;
        stream += `0.75 G 0.6 w 56 ${y} m 539 ${y} l S\n`;
        y -= 16;
      } else {
        y -= size * 1.45;
        stream += `BT /F${size >= 15 ? 2 : 1} ${size} Tf 56 ${y} Td (${escape(text)}) Tj ET\n`;
      }
    }
    objects.push(`<< /Length ${stream.length} >>\nstream\n${stream}endstream`);
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents ${objects.length} 0 R /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> >>`);
    kids.push(`${objects.length} 0 R`);
  }
  objects[1] = `<< /Type /Pages /Kids [${kids.join(' ')}] /Count ${kids.length} >>`;
  let out = '%PDF-1.4\n';
  const offsets = objects.map((body, i) => {
    const at = out.length;
    out += `${i + 1} 0 obj\n${body}\nendobj\n`;
    return at;
  });
  const xref = out.length;
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.map((at) => `${String(at).padStart(10, '0')} 00000 n \n`).join('')}`;
  out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, 'latin1');
}

/** A ZIP archive of `[name, bytes]` entries, stored as they are. */
export function zip(entries) {
  const parts = [];
  const directory = [];
  let at = 0;
  for (const [name, bytes] of entries) {
    const label = Buffer.from(name);
    const head = Buffer.alloc(30);
    head.writeUInt32LE(0x04034b50, 0);
    head.writeUInt16LE(20, 4); // version needed
    head.writeUInt16LE(0x0800, 6); // names are UTF-8
    head.writeUInt32LE(0x5a210000, 10); // 1 January 2025, midnight
    head.writeUInt32LE(zlib.crc32(bytes), 14);
    head.writeUInt32LE(bytes.length, 18);
    head.writeUInt32LE(bytes.length, 22);
    head.writeUInt16LE(label.length, 26);
    const entry = Buffer.alloc(46);
    entry.writeUInt32LE(0x02014b50, 0);
    entry.writeUInt16LE(20, 4);
    head.copy(entry, 6, 4, 30); // the same fields, in the same order
    entry.writeUInt32LE(at, 42);
    directory.push(entry, label);
    parts.push(head, label, bytes);
    at += 30 + label.length + bytes.length;
  }
  const size = directory.reduce((sum, part) => sum + part.length, 0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(size, 12);
  end.writeUInt32LE(at, 16);
  return Buffer.concat([...parts, ...directory, end]);
}

const SOURDOUGH = `# Sourdough, the weekend loaf

Makes one loaf. Start on Friday evening, bake on Sunday morning.

## Ingredients

| Ingredient              | Amount |
|-------------------------|-------:|
| Bread flour             |  450 g |
| Wholemeal flour         |   50 g |
| Water, lukewarm         |  360 g |
| Starter, fed and bubbly |  100 g |
| Salt                    |   10 g |

## Friday evening

Feed the starter: 30 g starter, 60 g flour, 60 g water. Leave it on the counter overnight.
It is ready when a spoonful floats in a glass of water.

## Saturday

1. Mix the flours and the water until no dry flour is left. Rest for 45 minutes.
2. Add the starter and the salt. Squeeze them in with wet hands.
3. Fold the dough four times, once every 30 minutes: pull one side up, lay it over, turn
   the bowl a quarter.
4. Leave it until it has grown by half and wobbles (3 to 5 hours, depending on the kitchen).
5. Shape it on a floured board, seam side up into the basket, and into the fridge overnight.

## Sunday morning

Heat the oven with the pot in it to 250 °C. Turn the loaf out onto baking paper, score it
with one long cut, and bake it

- 25 minutes with the lid on,
- 20 minutes with the lid off, at 220 °C, until it is deep brown.

Let it cool for at least an hour before cutting. This is the hard part.

## Notes

- 2026-02-08: a little flat. The starter was past its peak; feed it later next time.
- 2026-03-01: best one so far. 15 g more water, and the fridge for 14 hours.
- 2026-04-19: with 80 g of toasted walnuts folded in at the second fold. Keep this.
`;

const NOTES = `# Notes

## This week

- Renew the library card
- Bike: new brake pads, front
- Call the plumber about the kitchen tap
- Book the train for the first weekend of December

## Ideas

- A shelf above the desk for the weather station display
- Print the Norway photos, the fjord one large
`;

const TODO = `water the tomatoes
return the library books
order brake pads
back up the phone
`;

const PACKING = `# Packing list, Norway

- [x] Rain jacket, rain trousers
- [x] Hiking boots, two pairs of wool socks
- [x] Head torch, spare batteries
- [x] Camera, both lenses, tripod
- [ ] Power bank
- [ ] Thermos
- [ ] Ferry tickets (printed)
- [ ] Map of the national park
`;

const README_STATION = `# Weather station

A small station on the balcony: temperature, humidity, pressure and wind, one reading a
minute, sent over the home network to the display on the desk.

## Parts

- A microcontroller board with Wi-Fi
- A combined temperature, humidity and pressure sensor
- A cup anemometer with a reed switch
- A solar panel, a charge controller and one lithium cell

## Layout

    firmware/    what runs on the board
    data/        one CSV file per month
    enclosure/   the drawing of the housing
`;

const MAIN_PY = `"""Reads the sensors once a minute and sends the reading to the display."""
import time

from sensors import read_climate, read_wind
from uplink import send

INTERVAL = 60


def main():
    while True:
        started = time.monotonic()
        reading = {**read_climate(), "wind_ms": read_wind(seconds=10)}
        send(reading)
        time.sleep(max(0, INTERVAL - (time.monotonic() - started)))


if __name__ == "__main__":
    main()
`;

const SENSORS_PY = `"""The climate sensor on the I2C bus and the anemometer on a pulse counter."""
from board import climate, pulses

METRES_PER_PULSE = 0.34


def read_climate():
    t, h, p = climate.read()
    return {"temp_c": round(t, 1), "humidity": round(h), "pressure_hpa": round(p, 1)}


def read_wind(seconds):
    return round(pulses.count(seconds) * METRES_PER_PULSE / seconds, 1)
`;

function readings(year, month, days) {
  const rows = ['time,temp_c,humidity,pressure_hpa,wind_ms'];
  for (let day = 1; day <= days; day += 1) {
    for (let hour = 0; hour < 24; hour += 1) {
      const n = day * 24 + hour;
      const temp = 9 + 5 * Math.sin((hour - 9) / 24 * 2 * Math.PI) + fbm1(n / 30, month, 3) * 6;
      const wind = Math.max(0, 3 + fbm1(n / 9, month + 5, 3) * 7);
      rows.push(`${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}T${String(hour).padStart(2, '0')}:00,${temp.toFixed(1)},${Math.round(72 + fbm1(n / 20, month + 9, 2) * 30)},${(1013 + fbm1(n / 60, month + 2, 2) * 24).toFixed(1)},${wind.toFixed(1)}`);
    }
  }
  return `${rows.join('\n')}\n`;
}

const BUDGET = `month,rent,groceries,transport,utilities,savings
2026-01,980,312,64,141,300
2026-02,980,298,64,152,300
2026-03,980,331,71,133,300
2026-04,980,305,64,118,350
2026-05,980,322,89,96,350
2026-06,980,340,64,88,350
2026-07,980,356,132,84,250
2026-08,980,319,64,86,350
2026-09,980,327,64,97,350
2026-10,980,334,71,124,350
`;

const ENCLOSURE = `<svg xmlns="http://www.w3.org/2000/svg" width="480" height="320" viewBox="0 0 480 320">
<rect width="480" height="320" fill="#f6f4ee"/>
<g fill="none" stroke="#2b4a66" stroke-width="2">
<rect x="150" y="70" width="180" height="150" rx="10"/>
<path d="M150 110h180M150 150h180M150 190h180"/>
<path d="M240 70V30M210 30h60"/>
<circle cx="210" cy="30" r="9"/><circle cx="270" cy="30" r="9"/>
<path d="M240 220v60M200 280h80"/>
</g>
<text x="240" y="306" font-family="sans-serif" font-size="13" text-anchor="middle" fill="#2b4a66">louvred housing, front view</text>
</svg>
`;

const GARDEN = `<svg xmlns="http://www.w3.org/2000/svg" width="640" height="420" viewBox="0 0 640 420">
<rect width="640" height="420" fill="#eef3e6"/>
<g stroke="#4f6b3a" stroke-width="2">
<rect x="40" y="40" width="250" height="120" rx="6" fill="#cfe0b8"/>
<rect x="40" y="190" width="250" height="190" rx="6" fill="#dbe7c4"/>
<rect x="330" y="40" width="270" height="70" rx="6" fill="#e7d9b8"/>
<rect x="330" y="140" width="120" height="240" rx="6" fill="#cfe0b8"/>
<circle cx="535" cy="270" r="70" fill="#b9d3a0"/>
</g>
<g font-family="sans-serif" font-size="15" fill="#2f4424" text-anchor="middle">
<text x="165" y="105">tomatoes, basil</text><text x="165" y="290">potatoes</text><text x="465" y="80">herbs</text>
<text x="390" y="265">beans</text><text x="535" y="275">apple tree</text>
</g>
</svg>
`;

const INDEX_HTML = `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<title>Balcony weather</title>
<link rel="stylesheet" href="style.css">
<h1>Balcony weather</h1>
<p>Readings from the station on the balcony, one a minute.</p>
</html>
`;

const STYLE_CSS = `body { font: 16px/1.5 system-ui, sans-serif; max-width: 40rem; margin: 3rem auto; padding: 0 1rem; }
h1 { font-size: 1.6rem; }
`;

// --- the tree ------------------------------------------------------------------------------

/**
 * Writes the demo files below `dir` and sets their modification times. `only`: a filter on
 * the paths, for a part of the tree.
 */
export async function makeDemo(dir, only = () => true) {
  const made = [];
  const add = async (rel, date, write) => {
    if (!only(rel)) return;
    const file = path.join(dir, rel);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const content = await write(file);
    if (content !== undefined) fs.writeFileSync(file, content);
    const when = new Date(`${date}:00Z`);
    fs.utimesSync(file, when, when);
    made.push(rel);
  };

  await add('notes.md', '2026-11-09T18:42', () => NOTES);
  await add('todo.txt', '2026-11-12T07:58', () => TODO);
  await add('budget-2026.csv', '2026-11-01T09:15', () => BUDGET);
  await add('floor-plan.pdf', '2025-03-18T16:20', () => pdf([[
    [22, 'Floor plan, second floor'], [0, ''],
    [11, 'Hall 6.2 m2'], [11, 'Kitchen 11.8 m2'], [11, 'Living room 24.5 m2'], [11, 'Bedroom 14.1 m2'], [11, 'Study 9.4 m2'], [11, 'Bathroom 5.6 m2'], [11, 'Balcony 4.0 m2'],
    [0, ''], [15, 'Total 75.6 m2'],
  ]]));
  await add('garden-plan.svg', '2026-04-02T19:27', () => GARDEN);
  await add('voice-memo.m4a', '2026-10-21T08:14', (file) => tune(file, 37, [146.83, 220, 293.66], 3));
  await add('wallpaper.jpg', '2026-08-30T10:11', (file) => photo(file, 'wallpaper', 2880, 1800));

  await add('Documents/Recipes/sourdough.md', '2026-04-19T11:20', () => SOURDOUGH);
  await add('Documents/Recipes/lentil-soup.md', '2025-11-23T19:05', () => '# Lentil soup\n\nRed lentils, an onion, two carrots, cumin, a tin of tomatoes, lemon at the end.\nSimmer for 25 minutes.\n');
  await add('Documents/Recipes/plum-cake.md', '2026-09-06T15:40', () => '# Plum cake\n\nA sheet of yeast dough, plums cut in quarters and set upright, cinnamon sugar.\n35 minutes at 180 °C.\n');
  await add('Documents/Travel/packing-list.md', '2026-08-12T21:10', () => PACKING);
  await add('Documents/Travel/itinerary-norway.pdf', '2026-08-10T20:31', () => pdf([[
    [22, 'Norway, 14 to 23 August'], [0, ''],
    [15, 'Day 1 to 2: the city'], [11, 'Arrive by train in the evening. Harbour walk, fish market, the funicular at sunset.'],
    [15, 'Day 3 to 5: the fjord'], [11, 'Ferry in the morning. Two nights in the cabin by the water; kayaks can be hired at the pier.'],
    [15, 'Day 6 to 8: the plateau'], [11, 'Bus to the trailhead. Hut to hut, about 14 km a day. Check the weather the evening before.'],
    [15, 'Day 9 to 10: back'], [11, 'Night train. Seats are reserved; the dining car opens at six.'],
    [0, ''], [10, 'Bring cash for the huts. The last shop is at the ferry pier.'],
  ]]));
  await add('Documents/Travel/tickets.pdf', '2026-08-11T08:02', () => pdf([[[22, 'Ferry tickets'], [0, ''], [11, 'Two adults, one way, morning departure. Show this page at the pier.']]]));
  await add('Documents/Household/manuals.pdf', '2025-06-14T10:12', () => pdf(Array.from({ length: 24 }, (_, i) => [[22, `Appliance manuals, page ${i + 1}`], [0, ''], ...Array.from({ length: 30 }, (__, line) => [10, `Section ${i + 1}.${line + 1}: keep the appliance dry, level and out of direct sunlight.`])])));
  await add('Documents/Household/meter-readings.csv', '2026-10-31T17:48', () => 'date,electricity_kwh,water_m3,heating_units\n2026-07-31,48211,312.4,1904\n2026-08-31,48390,318.9,1904\n2026-09-30,48577,325.1,1911\n2026-10-31,48802,331.6,1967\n');
  await add('Documents/Household/bike-insurance.pdf', '2026-03-02T12:26', () => pdf([[[22, 'Bicycle insurance'], [0, ''], [11, 'Covers theft and damage. Renewal every March. Keep the frame number with this page.']]]));

  for (const [name, scene, date] of [
    ['harbour-at-dusk.jpg', 'ember', '2026-08-14T19:52'],
    ['fjord-from-the-ferry.jpg', 'fjord', '2026-08-16T08:47'],
    ['cabin-morning.jpg', 'morning', '2026-08-17T06:31'],
    ['northern-lights.jpg', 'aurora', '2026-08-18T22:58'],
    ['plateau-ridges.jpg', 'dusk', '2026-08-20T20:14'],
    ['green-valley.jpg', 'hills', '2026-08-21T13:05'],
    ['midnight-sun.jpg', 'midnight', '2026-08-15T23:40'],
    ['rain-coming-in.jpg', 'rain', '2026-08-19T15:26'],
    ['trail-above-the-fjord.jpg', 'trail', '2026-08-16T12:18'],
  ]) await add(`Photos/2026/Norway/${name}`, date, (file) => photo(file, scene));
  await add('Photos/2026/Norway/night-lake.jpg', '2026-08-18T23:21', (file) => photo(file, 'lake', 2000, 3000));
  await add('Photos/2026/Norway/fjord-timelapse.mp4', '2026-08-16T09:30', (file) => film(file, 10, 1920, 1080, (t) => ({
    ...SCENES.fjord,
    sky: SCENES.fjord.sky.map(([at, rgb], i) => [at, mix3(rgb, SCENES.ember.sky[i + (i > 1 ? 1 : 0)][1], t * 0.55)]),
    sun: { x: 0.3 + t * 0.06, y: 0.2 + t * 0.2, radius: 0.036, rgb: [255, 244, 214], glow: 0.4 + t * 0.2 },
    clouds: { ...SCENES.fjord.clouds, rgb: mix3([255, 255, 255], [255, 200, 170], t * 0.7), drift: t * 0.9 },
    water: { ...SCENES.fjord.water, phase: t * 14 },
  })));
  for (const [name, scene, date] of [
    ['dunes.jpg', 'dunes', '2025-05-03T16:22'],
    ['evening-walk.jpg', 'dusk', '2025-10-12T18:09'],
    ['first-snow.jpg', 'morning', '2025-12-02T09:44'],
  ]) await add(`Photos/2025/${name}`, date, (file) => photo(file, scene, 2400, 1600));
  await add('photos-2025.zip', '2026-01-04T17:33', () => zip(['dunes.jpg', 'evening-walk.jpg', 'first-snow.jpg'].map((name) => [name, fs.readFileSync(path.join(dir, 'Photos/2025', name))])));
  await add('Videos/aurora-timelapse.mp4', '2026-08-18T23:50', (file) => film(file, 8, 1280, 720, (t) => ({
    ...SCENES.aurora,
    aurora: { ...SCENES.aurora.aurora, phase: t * 0.5, strength: 0.7 + 0.25 * Math.sin(t * 5) },
  })));

  await add('Music/Demos/evening-loop.mp3', '2026-02-21T22:17', (file) => tune(file, 48, [220, 277.18, 329.63, 440], 2));
  await add('Music/Demos/riff-idea-03.mp3', '2026-05-30T23:02', (file) => tune(file, 31, [196, 246.94, 293.66], 5));
  await add('Music/Demos/slow-chords.mp3', '2026-10-04T21:36', (file) => tune(file, 64, [174.61, 220, 261.63, 349.23], 0.5));

  await add('Projects/weather-station/README.md', '2026-10-18T14:03', () => README_STATION);
  await add('Projects/weather-station/firmware/main.py', '2026-10-18T13:51', () => MAIN_PY);
  await add('Projects/weather-station/firmware/sensors.py', '2026-09-27T16:40', () => SENSORS_PY);
  await add('Projects/weather-station/data/2026-09.csv', '2026-09-30T23:59', () => readings(2026, 9, 30));
  await add('Projects/weather-station/data/2026-10.csv', '2026-10-31T23:59', () => readings(2026, 10, 31));
  await add('Projects/weather-station/enclosure/housing.svg', '2026-07-05T10:28', () => ENCLOSURE);
  await add('Projects/website/index.html', '2026-06-11T20:45', () => INDEX_HTML);
  await add('Projects/website/style.css', '2026-06-11T20:47', () => STYLE_CSS);
  return made;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const dir = process.argv[2];
  if (!dir) {
    console.error('usage: node content.mjs <directory>');
    process.exit(2);
  }
  const made = await makeDemo(path.resolve(dir));
  console.log(`${made.length} files in ${path.resolve(dir)}`);
}
