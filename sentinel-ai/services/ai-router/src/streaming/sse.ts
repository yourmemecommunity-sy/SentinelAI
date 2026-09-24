const dataOf = (raw: string): string =>
  raw.split(/\r?\n/).filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trimStart()).join("\n");

/** Minimal Server-Sent-Events parser over a fetch body. Yields the payload of each event's `data:` lines. */
export async function* parseSse(body: ReadableStream<Uint8Array>, maxBufferBytes = 1_000_000): AsyncGenerator<string> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      if (buffer.length > maxBufferBytes) throw new RangeError("SSE buffer too large");
      let m: RegExpExecArray | null;
      while ((m = /\r?\n\r?\n/.exec(buffer)) !== null) {
        const data = dataOf(buffer.slice(0, m.index));
        buffer = buffer.slice(m.index + m[0].length);
        if (data) yield data;
      }
    }
    const tail = dataOf(buffer);
    if (tail) yield tail;
  } finally {
    reader.releaseLock();
  }
}
