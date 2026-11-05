/**
 * Contract between the renderer bridge (createTauriGp) and the Rust backend (src-tauri), read from
 * the Rust sources so that drift on either side fails CI without building the app:
 * - every GpApi method reaches a command registered in `generate_handler!` (main.rs) with exactly
 *   the argument keys Tauri derives from the command's parameters (snake_case → camelCase);
 * - every registered command is used by the bridge and allowed for the main window only
 *   (capabilities/main.json);
 * - the bridge subscribes to exactly the events the backend emits, and the backend emits them to
 *   the main window only.
 */
import { describe, expect, it, vi } from 'vitest';
import type { GpApi } from '@shared/ipc';
import { createTauriGp, TAURI_EVENTS, type TauriDeps } from './tauri';

// The web tsconfig has no Node types: load fs dynamically with a minimal local type (as in
// ConnectToggle.css.test.ts). Paths are relative to the project root (the vitest root).
type Fs = {
  readFileSync(path: string, encoding: 'utf8'): string;
  readdirSync(path: string, options?: { recursive: boolean }): string[];
};
const FS_MODULE = 'node:fs';
const fs = (await import(/* @vite-ignore */ FS_MODULE)) as Fs;
const TAURI_DIR = 'src-tauri';
const read = (rel: string): string => fs.readFileSync(`${TAURI_DIR}/${rel}`, 'utf8');

/** Parameters Tauri injects (not sent by the webview). */
const INJECTED = new Set(['State', 'Webview', 'AppHandle', 'Window', 'WebviewWindow']);

const snakeToCamel = (s: string): string => s.replace(/_([a-z])/g, (_m, c: string) => c.toUpperCase());

function registeredCommands(): string[] {
  const m = /generate_handler!\[([\s\S]*?)\]/.exec(read('src/main.rs'));
  if (!m) throw new Error('generate_handler! not found in src-tauri/src/main.rs');
  return [...(m[1] ?? '').matchAll(/commands::(\w+)/g)].map((x) => x[1] ?? '');
}

interface RustParam {
  name: string;
  type: string;
}

/** `#[tauri::command] … fn name<…>(params)` → params (name + outer type) per command. */
function commandParams(): Map<string, RustParam[]> {
  const src = read('src/commands.rs');
  const out = new Map<string, RustParam[]>();
  for (const m of src.matchAll(/#\[tauri::command\][\s\S]*?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\(([\s\S]*?)\)\s*->/g)) {
    const params = [...(m[2] ?? '').matchAll(/\b([a-z_][a-z0-9_]*)\s*:\s*([A-Za-z]+)(<[^\n,]*(?:,[^\n,]*)?>)?/g)].map(
      (p) => ({ name: p[1] ?? '', type: (p[2] ?? '') + (p[3] ?? '') }),
    );
    out.set(m[1] ?? '', params);
  }
  return out;
}

interface Call {
  method: string;
  cmd?: string;
  argKeys?: string[];
  event?: string;
}

/** Calls every GpApi method (with every optional argument given) and records what it does. */
function exerciseBridge(): Call[] {
  let current = '';
  const calls: Call[] = [];
  const invoke = vi.fn(async (cmd: string, args?: Record<string, unknown>) => {
    calls.push({ method: current, cmd, argKeys: Object.keys(args ?? {}).sort() });
    return undefined;
  });
  const listen = vi.fn(async (event: string) => {
    calls.push({ method: current, event });
    return () => undefined;
  });
  const gp = createTauriGp({ invoke, listen } as unknown as TauriDeps);

  const samples: Record<string, unknown[]> = {
    'profiles.save': [{ name: 'W', portalUrl: 'vpn.example.com', authMode: 'auto', savePassword: true }, 'pw'],
    'profiles.remove': ['id-1'],
    'vpn.connect': ['p1', { gateway: 'gw', password: 'pw' }],
    'vpn.answerPrompt': ['q1', '123'],
    'settings.set': [{ theme: 'dark' }],
    'system.openExternal': ['https://example.com/'],
  };
  for (const [area, methods] of Object.entries(gp as unknown as Record<string, Record<string, unknown>>)) {
    for (const [name, fn] of Object.entries(methods)) {
      current = `${area}.${name}`;
      const before = calls.length;
      const ret = (fn as (...a: unknown[]) => unknown)(...(samples[current] ?? ['a', 'b', 'c']));
      if (typeof ret === 'function') (ret as () => void)(); // unsubscribe
      if (ret instanceof Promise) ret.catch(() => undefined);
      expect(calls.length, `${current} neither invoked a command nor subscribed`).toBe(before + 1);
    }
  }
  return calls;
}

describe('bridge ↔ src-tauri command contract', () => {
  const registered = registeredCommands();
  const params = commandParams();
  const calls = exerciseBridge();
  const commandCalls = calls.filter((c) => c.cmd !== undefined);

  it('reads a non-trivial contract from the Rust sources', () => {
    expect(registered.length).toBeGreaterThanOrEqual(14);
    expect(new Set(registered).size).toBe(registered.length);
    for (const cmd of registered) expect(params.has(cmd), `#[tauri::command] fn ${cmd} not found`).toBe(true);
  });

  it.each(commandCalls.map((c) => [c.method, c] as const))('%s calls a registered command', (_m, call) => {
    expect(registered).toContain(call.cmd);
  });

  it.each(commandCalls.map((c) => [c.method, c] as const))(
    '%s sends exactly the arguments the command declares',
    (_m, call) => {
      const declared = (params.get(call.cmd!) ?? []).filter((p) => !INJECTED.has(p.type.replace(/<.*/, '')));
      expect(call.argKeys).toEqual(declared.map((p) => snakeToCamel(p.name)).sort());
      // The bridge drops `undefined` arguments, so every webview-supplied parameter must be optional.
      for (const p of declared) expect(p.type, `${call.cmd}(${p.name})`).toMatch(/^Option</);
    },
  );

  it('every registered command is used by the bridge', () => {
    const used = new Set(commandCalls.map((c) => c.cmd));
    expect(registered.filter((c) => !used.has(c))).toEqual([]);
  });

  it('the capability grants exactly the registered commands, to the main window only', () => {
    const cap = JSON.parse(read('capabilities/main.json')) as {
      windows: string[];
      local?: boolean;
      remote?: unknown;
      permissions: string[];
    };
    expect(cap.windows).toEqual(['main']);
    expect(cap.local).toBe(true);
    expect(cap.remote).toBeUndefined();
    const appPermissions = cap.permissions.filter((p) => p.startsWith('allow-')).sort();
    expect(appPermissions).toEqual(registered.map((c) => `allow-${c.replace(/_/g, '-')}`).sort());
    const capabilityFiles = fs.readdirSync(`${TAURI_DIR}/capabilities`);
    expect(capabilityFiles, 'another capability could grant commands to other windows').toEqual(['main.json']);
  });
});

describe('bridge ↔ src-tauri event contract', () => {
  const appState = read('src/app_state.rs');
  const backendEvents = new Map(
    [...appState.matchAll(/const (EV_\w+): &str = "([^"]+)";/g)].map((m) => [m[1], m[2]] as const),
  );

  it('the bridge listens to exactly the events the backend defines', () => {
    expect([...backendEvents.values()].sort()).toEqual(Object.values(TAURI_EVENTS).sort());
    const subscribed = exerciseBridge()
      .filter((c) => c.event !== undefined)
      .map((c) => c.event);
    expect([...new Set(subscribed)].sort()).toEqual(Object.values(TAURI_EVENTS).sort());
  });

  it('the backend emits events to the main window only, never broadcast', () => {
    const srcDir = `${TAURI_DIR}/src`;
    const files = fs.readdirSync(srcDir, { recursive: true }).filter((f) => f.endsWith('.rs') && !f.includes('tests'));
    const emits: string[] = [];
    for (const f of files) {
      const text = fs.readFileSync(`${srcDir}/${f}`, 'utf8');
      for (const m of text.matchAll(/\.(emit\w*)\(\s*([^,)]*)/g)) emits.push(`${f}: ${m[1]}(${m[2]}`);
    }
    expect(emits.length).toBeGreaterThanOrEqual(backendEvents.size);
    for (const e of emits) expect(e).toMatch(/: emit_to\(MAIN$/);
    // Every event constant is actually emitted.
    for (const name of backendEvents.keys()) expect(appState).toMatch(new RegExp(`emit_to\\(MAIN, ${name}\\b`));
  });
});

// Keeps the `GpApi` import meaningful: the bridge must implement the full interface.
const _typecheck: (deps: TauriDeps) => GpApi = createTauriGp;
void _typecheck;
