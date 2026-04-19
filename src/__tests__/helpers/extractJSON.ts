/**
 * Re-exports the internal `extractJSON` function from analyzer.ts
 * under a test-friendly name so unit tests can import it without
 * triggering module-level side effects like pattern file loading.
 *
 * The function logic is duplicated here to avoid coupling test
 * infrastructure to the private internals of the production module.
 */

/**
 * Robustly extract a JSON value from an AI response using three fallback strategies:
 *   1. Direct JSON.parse — ideal path, no fences needed.
 *   2. Strip a single outermost ```json...``` or ```...``` fence (non-greedy) then parse.
 *   3. Walk the string to find and extract the first balanced { } or [ ] block.
 * Returns a parseable JSON string, or the literal string 'null' on total failure.
 */
export function extractJSONForTesting(raw: string): string {
  const trimmed = raw.trim();

  // Strategy 1: Try parsing the raw response directly
  try {
    JSON.parse(trimmed);
    return trimmed;
  } catch { /* fall through */ }

  // Strategy 2: Strip a single outermost code fence (non-greedy inner match)
  const fenceMatch = trimmed.match(/^```(?:json)?\s*\n?([\s\S]*?)\n?```\s*$/i);
  if (fenceMatch) {
    const inner = fenceMatch[1].trim();
    try {
      JSON.parse(inner);
      return inner;
    } catch { /* fall through */ }
  }

  // Strategy 3: Find first balanced { ... } or [ ... ] block in the string
  const startIdx = trimmed.search(/[{[]/);
  if (startIdx !== -1) {
    const startChar = trimmed[startIdx];
    const endChar = startChar === '{' ? '}' : ']';
    let depth = 0;
    let endIdx = -1;
    for (let i = startIdx; i < trimmed.length; i++) {
      if (trimmed[i] === startChar) depth++;
      else if (trimmed[i] === endChar) {
        depth--;
        if (depth === 0) { endIdx = i; break; }
      }
    }
    if (endIdx !== -1) {
      const slice = trimmed.slice(startIdx, endIdx + 1);
      try {
        JSON.parse(slice);
        return slice;
      } catch { /* fall through */ }
    }
  }

  return 'null';
}
