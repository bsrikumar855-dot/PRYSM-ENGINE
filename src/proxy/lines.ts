// Newline-delimited framing with a hard per-line byte cap. An oversize line is discarded (reported once) up to
// and including its terminating newline, so it can never be buffered without bound.
export class LineSplitter {
  readonly #max: number;
  readonly #onLine: (line: Buffer) => void;
  readonly #onOversize: () => void;
  #chunks: Buffer[] = [];
  #size = 0;
  #discarding = false;

  constructor(max: number, onLine: (line: Buffer) => void, onOversize: () => void) {
    this.#max = max;
    this.#onLine = onLine;
    this.#onOversize = onOversize;
  }

  push(input: Buffer): void {
    let chunk = input;
    for (;;) {
      const idx = chunk.indexOf(0x0a);
      if (idx < 0) {
        if (this.#discarding) return;
        this.#size += chunk.length;
        if (this.#size > this.#max) {
          this.#chunks = [];
          this.#size = 0;
          this.#discarding = true;
          this.#onOversize();
        } else {
          this.#chunks.push(chunk);
        }
        return;
      }
      const piece = chunk.subarray(0, idx);
      chunk = chunk.subarray(idx + 1);
      if (this.#discarding) {
        this.#discarding = false;
      } else if (this.#size + piece.length > this.#max) {
        this.#onOversize();
      } else {
        const line = this.#chunks.length === 0 ? piece : Buffer.concat([...this.#chunks, piece]);
        this.#emit(line);
      }
      this.#chunks = [];
      this.#size = 0;
      if (chunk.length === 0) return;
    }
  }

  /** End of stream: a trailing partial line is processed (unless it was already being discarded). */
  end(): void {
    if (this.#discarding) {
      this.#discarding = false;
    } else if (this.#size > 0) {
      const line = Buffer.concat(this.#chunks);
      this.#chunks = [];
      this.#size = 0;
      this.#emit(line);
    }
  }

  #emit(raw: Buffer): void {
    let line = raw;
    if (line.length > 0 && line[line.length - 1] === 0x0d) line = line.subarray(0, line.length - 1);
    if (line.length === 0) return;
    let blank = true;
    for (const b of line) if (b !== 0x20 && b !== 0x09 && b !== 0x0d) { blank = false; break; }
    if (blank) return; // whitespace-only lines are ignored like blank lines
    this.#onLine(line);
  }
}
