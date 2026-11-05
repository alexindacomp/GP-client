// Generates the tray and application icons (PNG) without external dependencies.
// Usage: node scripts/generate-icons.mjs
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

const root = path.resolve(import.meta.dirname, '..');

function crc32(buf) {
  return zlib.crc32(buf) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}

function encodePng(size, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

// --- shapes in normalised coordinates (0..1) -------------------------------
const HALF_W = 0.36;
function inShield(x, y, inset = 0) {
  const hw = HALF_W - inset;
  const top = 0.08 + inset;
  const mid = 0.52;
  const bottom = 0.94 - inset * 1.4;
  if (y < top || y > bottom) return false;
  const dx = Math.abs(x - 0.5);
  if (y <= mid) {
    // slightly rounded top corners
    const r = 0.08;
    if (dx > hw) return false;
    if (y < top + r && dx > hw - r) {
      const cx = hw - r;
      const cy = top + r;
      return (dx - cx) ** 2 + (y - cy) ** 2 <= r * r;
    }
    return true;
  }
  const t = (y - mid) / (bottom - mid);
  return dx <= hw * Math.sqrt(Math.max(0, 1 - t * t));
}
function inKeyhole(x, y) {
  const c = (x - 0.5) ** 2 + (y - 0.42) ** 2 <= 0.1 ** 2;
  const stem = Math.abs(x - 0.5) <= 0.045 && y >= 0.42 && y <= 0.68;
  return c || stem;
}
function inDot(x, y) {
  return (x - 0.5) ** 2 + (y - 0.5) ** 2 <= 0.12 ** 2;
}

function render(size, shade) {
  const ss = 4;
  const buf = Buffer.alloc(size * size * 4);
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let r = 0,
        g = 0,
        b = 0,
        a = 0;
      for (let sy = 0; sy < ss; sy++) {
        for (let sx = 0; sx < ss; sx++) {
          const x = (px + (sx + 0.5) / ss) / size;
          const y = (py + (sy + 0.5) / ss) / size;
          const c = shade(x, y);
          if (c) {
            r += c[0] * c[3];
            g += c[1] * c[3];
            b += c[2] * c[3];
            a += c[3];
          }
        }
      }
      const n = ss * ss;
      const i = (py * size + px) * 4;
      if (a > 0) {
        buf[i] = Math.round(r / a);
        buf[i + 1] = Math.round(g / a);
        buf[i + 2] = Math.round(b / a);
      }
      buf[i + 3] = Math.round((a / n) * 255);
    }
  }
  return buf;
}

const hex = (h) => [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16), 1];
const WHITE = [255, 255, 255, 1];
const BLACK = [0, 0, 0, 1];

const colored = (color) => (x, y) => (inShield(x, y) ? (inKeyhole(x, y) ? WHITE : color) : null);

// macOS template images: black + alpha only, states differ by shape.
const templates = {
  disconnected: (x, y) => (inShield(x, y) && !inShield(x, y, 0.08) ? BLACK : null),
  connecting: (x, y) => ((inShield(x, y) && !inShield(x, y, 0.08)) || inDot(x, y) ? BLACK : null),
  connected: (x, y) => (inShield(x, y) && !inKeyhole(x, y) ? BLACK : null),
};

const states = {
  disconnected: hex('#8A8F98'),
  connecting: hex('#C98A0B'),
  connected: hex('#1F883D'),
};

function write(rel, size, shade) {
  const file = path.join(root, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, encodePng(size, render(size, shade)));
  console.log('wrote', rel);
}

for (const [state, color] of Object.entries(states)) {
  write(`resources/tray/tray-${state}.png`, 16, colored(color));
  write(`resources/tray/tray-${state}@2x.png`, 32, colored(color));
  write(`resources/tray/tray-${state}Template.png`, 16, templates[state]);
  write(`resources/tray/tray-${state}Template@2x.png`, 32, templates[state]);
}
write('resources/icon.png', 256, colored(hex('#0067C0')));
