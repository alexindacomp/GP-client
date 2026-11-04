/**
 * openconnect.exe on Windows (and the UAC bridge) may emit CRLF line endings and
 * prompts terminated by a lone CR. Every recorded transcript is replayed with LF
 * and with CRLF in every chunking mode; the engine must behave identically.
 */
import fs from 'node:fs';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  createHarness,
  flush,
  loadTranscript,
  playUntilPrompt,
  PROFILE_ID,
  type PlayOptions,
} from '../__fixtures__/engine-harness';

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

const TRANSCRIPTS = fs
  .readdirSync(path.join(__dirname, '../__fixtures__/openconnect'))
  .filter((f) => f.endsWith('.txt'))
  .sort();

const MODES: [string, PlayOptions][] = [
  ['line by line', {}],
  ['re-chunked every 7 chars, prompts split 100 ms apart', { chunkSize: 7, splitPromptGapMs: 100 }],
  ['re-chunked every 1 char, prompts split 140 ms apart', { chunkSize: 1, splitPromptGapMs: 140 }],
  // CR and LF of the same line delivered in different reads
  ['re-chunked every 2 chars', { chunkSize: 2 }],
];

/** Plays a transcript to the end, answering every prompt, and returns what is observable. */
async function run(name: string, eol: 'lf' | 'crlf', play: PlayOptions) {
  const h = createHarness({ profile: { preferredGateway: 'gw-us.example.com' }, savedPassword: 'C0rrect-Horse' });
  await h.engine.connect(PROFILE_ID);
  await flush();
  const proc = h.spawner.last;
  let rest = loadTranscript(name, { eol });
  let answered = 0;
  while (rest.length > 0) {
    rest = await playUntilPrompt(proc, rest, play);
    for (const p of h.prompts.slice(answered)) {
      answered++;
      if (h.engine.getPendingPrompts().some((x) => x.id === p.id)) {
        await h.engine.answerPrompt(p.id, p.options?.[0] ?? '481516');
        await flush();
      }
    }
  }
  if (h.spawner.processes.length === 1) proc.exit(1);
  await flush();
  return {
    states: h.states,
    prompts: h.prompts.map(({ id: _id, ...p }) => p),
    written: h.spawner.processes.map((p) => p.written),
    // log lines without their timestamp
    log: h.logger.lines().map((l) => l.replace(/^\S+ /, '')),
    final: h.engine.getState(),
  };
}

describe.each(TRANSCRIPTS)('%s: CRLF output behaves exactly like LF', (name) => {
  it.each(MODES)('%s', async (_mode, play) => {
    const lf = await run(name, 'lf', play);
    const crlf = await run(name, 'crlf', play);
    expect(crlf).toEqual(lf);
    // and nothing leaks a carriage return into what the UI or the log sees
    expect(JSON.stringify(crlf)).not.toContain('\\r');
  });
});

it('covers all recorded transcripts', () => {
  expect(TRANSCRIPTS.length).toBeGreaterThanOrEqual(9);
});
