import { beforeAll, describe, expect, it } from 'vitest';

// CSS modules are proxied in the renderer test project (even with ?raw), so read the source file.
// The web tsconfig has no Node types: load fs dynamically with a minimal local type.
type Fs = { readFileSync(path: string, encoding: 'utf8'): string };
const FS_MODULE = 'node:fs';
let css = '';

beforeAll(async () => {
  const fs = (await import(/* @vite-ignore */ FS_MODULE)) as Fs;
  css = fs.readFileSync('src/renderer/src/screens/connect/ConnectToggle.module.css', 'utf8'); // relative to the project root (vitest root);
});

/** Declarations of the first rule whose selector is exactly `selector`. */
function rule(source: string, selector: string): string {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = new RegExp(`(?:^|\\})\\s*(?:/\\*[\\s\\S]*?\\*/\\s*)*${escaped}\\s*\\{([^}]*)\\}`).exec(source);
  if (!match?.[1]) throw new Error(`rule ${selector} not found`);
  return match[1];
}

// jsdom has no hit testing, so a decorative overlay stealing clicks (found on real Windows:
// the ring intercepted every mouse click on the toggle) can only be guarded at the CSS level.
describe('ConnectToggle styles', () => {
  it('the decorative ring overlay never intercepts pointer events', () => {
    const ring = rule(css, '.ring');
    expect(ring).toMatch(/position:\s*absolute/);
    expect(ring).toMatch(/pointer-events:\s*none/);
  });

  it('the toggle button is stacked above the ring', () => {
    const toggle = rule(css, '.toggle');
    expect(toggle).toMatch(/position:\s*relative/);
    expect(toggle).toMatch(/z-index:\s*1/);
  });
});
