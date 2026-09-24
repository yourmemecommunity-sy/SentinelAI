/** Newline-delimited JSON over a fetch body (Ollama streaming). Yields each non-empty line as a string. */
export async function* parseNdjson(body: ReadableStream<Uint8Array>, maxLineBytes = 1_000_000): AsyncGenerator<string> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let i: number;
      while ((i = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, i).trim();
        buffer = buffer.slice(i + 1);
        if (line) yield line;
      }
      if (buffer.length > maxLineBytes) throw new RangeError("NDJSON line too large");
    }
    if (buffer.trim()) yield buffer.trim();
  } finally {
    reader.releaseLock();
  }
}
