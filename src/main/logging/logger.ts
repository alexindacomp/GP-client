import fs from 'node:fs';
import path from 'node:path';
import { LogBuffer } from './log-buffer';
import { SecretRegistry } from './mask';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';
export type LogListener = (line: string) => void;

const MAX_FILE_BYTES = 5 * 1024 * 1024;
const LOG_FILE_NAME = 'gp-connect.log';

/**
 * Application log: masks secrets, keeps the last N lines in memory, appends to
 * `<logsDir>/gp-connect.log` (rotated to `.1` at 5 MiB) and notifies listeners.
 */
export class Logger {
  readonly secrets = new SecretRegistry();
  private readonly buffer: LogBuffer;
  private readonly listeners = new Set<LogListener>();
  private stream: fs.WriteStream | null = null;
  private fileBytes = 0;

  constructor(
    private readonly logsDir: string | null,
    capacity = 2000,
  ) {
    this.buffer = new LogBuffer(capacity);
    if (logsDir) this.openFile();
  }

  get filePath(): string | null {
    return this.logsDir ? path.join(this.logsDir, LOG_FILE_NAME) : null;
  }

  debug(source: string, msg: string): void {
    this.write('debug', source, msg);
  }
  info(source: string, msg: string): void {
    this.write('info', source, msg);
  }
  warn(source: string, msg: string): void {
    this.write('warn', source, msg);
  }
  error(source: string, msg: string, err?: unknown): void {
    const detail = err instanceof Error ? `: ${err.message}` : err ? `: ${String(err)}` : '';
    this.write('error', source, msg + detail);
  }

  /** Writes one log entry. Multi-line messages are split into separate lines. */
  write(level: LogLevel, source: string, msg: string): void {
    const ts = new Date().toISOString();
    for (const raw of msg.split(/\r?\n/)) {
      if (raw.trim() === '') continue;
      const line = `${ts} ${level.toUpperCase().padEnd(5)} [${source}] ${this.secrets.mask(raw)}`;
      this.buffer.push(line);
      this.appendToFile(line);
      for (const l of this.listeners) {
        try {
          l(line);
        } catch {
          // a broken listener must not break logging
        }
      }
    }
  }

  lines(): string[] {
    return this.buffer.snapshot();
  }

  onLine(listener: LogListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  close(): void {
    this.stream?.end();
    this.stream = null;
  }

  private openFile(): void {
    const file = this.filePath;
    if (!file || !this.logsDir) return;
    try {
      fs.mkdirSync(this.logsDir, { recursive: true, mode: 0o700 });
      if (process.platform !== 'win32') fs.chmodSync(this.logsDir, 0o700);
      this.fileBytes = fs.existsSync(file) ? fs.statSync(file).size : 0;
      this.stream = fs.createWriteStream(file, { flags: 'a', mode: 0o600 });
      this.stream.on('error', () => {
        // Disk full / permissions: keep the in-memory log working.
        this.stream = null;
      });
    } catch {
      this.stream = null;
    }
  }

  private appendToFile(line: string): void {
    if (!this.stream) return;
    const data = line + '\n';
    this.fileBytes += Buffer.byteLength(data);
    this.stream.write(data);
    if (this.fileBytes >= MAX_FILE_BYTES) this.rotate();
  }

  private rotate(): void {
    const file = this.filePath;
    if (!file) return;
    const old = this.stream;
    this.stream = null;
    old?.end(() => {
      try {
        fs.renameSync(file, `${file}.1`);
      } catch {
        // ignore: we'll keep appending to the current file
      }
    });
    // Open the new file after the old stream is flushed and renamed.
    old?.once('finish', () => this.openFile());
    this.fileBytes = 0;
  }
}
