/** Minimal helpers for the flat XML documents returned by GlobalProtect endpoints. */

const ENTITIES: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
};

export function decodeXmlEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z]+);/gi, (m, ent: string) => {
    if (ent[0] === '#') {
      const code = ent[1] === 'x' || ent[1] === 'X' ? parseInt(ent.slice(2), 16) : parseInt(ent.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : m;
    }
    return ENTITIES[ent.toLowerCase()] ?? m;
  });
}

function escapeTag(tag: string): string {
  return tag.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Text content of the first `<tag>` element (no nesting support — not needed for
 * prelogin/SAML documents). Returns `undefined` if the tag is absent, `''` if empty
 * or self-closing. CDATA sections are unwrapped.
 */
export function getTagText(xml: string, tag: string): string | undefined {
  const t = escapeTag(tag);
  const full = new RegExp(`<${t}(?:\\s[^>]*)?>([\\s\\S]*?)</${t}\\s*>`, 'i').exec(xml);
  if (full) {
    const raw = full[1] ?? '';
    const cdata = /^\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*$/.exec(raw);
    return cdata ? (cdata[1] ?? '') : decodeXmlEntities(raw.trim());
  }
  if (new RegExp(`<${t}(?:\\s[^>]*)?/>`, 'i').test(xml)) return '';
  return undefined;
}
