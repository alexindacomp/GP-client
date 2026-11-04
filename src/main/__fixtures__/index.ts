import fs from 'node:fs';
import path from 'node:path';

export function fixture(name: string): string {
  return fs.readFileSync(path.join(__dirname, name), 'utf8');
}
