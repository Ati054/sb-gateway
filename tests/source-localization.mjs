export function normalizeLocalizedSource(source) {
  return source
    .replace(/\r\n?/g, "\n")
    .replace(/=\{tr\(("(?:\\.|[^"\\])*")\)\}/g, (_match, value) => `=${value}`)
    .replace(/\{tr\(("(?:\\.|[^"\\])*")\)\}/g, (_match, value) => JSON.parse(value))
    .replace(/tr\(("(?:\\.|[^"\\])*")\)/g, (_match, value) => value);
}
