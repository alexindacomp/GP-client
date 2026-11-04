/** Fixed-capacity ring buffer of log lines. */
export class LogBuffer {
  private readonly lines: string[] = [];

  constructor(private readonly capacity = 2000) {
    if (!Number.isInteger(capacity) || capacity <= 0) {
      throw new RangeError(`LogBuffer capacity must be a positive integer, got ${capacity}`);
    }
  }

  push(line: string): void {
    this.lines.push(line);
    if (this.lines.length > this.capacity) {
      this.lines.splice(0, this.lines.length - this.capacity);
    }
  }

  snapshot(): string[] {
    return [...this.lines];
  }

  get size(): number {
    return this.lines.length;
  }
}
