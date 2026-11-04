import fs from 'node:fs';
import path from 'node:path';

/**
 * Reads a fixture. `GP_FIXTURE_EOL=crlf` serves every fixture with CRLF line
 * endings, which is what a Windows checkout with core.autocrlf=true produces;
 * run `GP_FIXTURE_EOL=crlf npx vitest run` to check the whole suite against it.
 */
export function fixture(name: string): string {
  const text = fs.readFileSync(path.join(__dirname, name), 'utf8');
  return process.env.GP_FIXTURE_EOL === 'crlf' ? toCrlf(text) : text;
}

/** LF (or mixed) → CRLF. */
export function toCrlf(text: string): string {
  return text.replace(/\r?\n/g, '\r\n');
}
