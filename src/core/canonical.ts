// Canonical JSON — deterministic serialization for signing
// Sorts keys alphabetically, omits null/undefined values

export function canonicalize(obj: unknown): string {
  if (obj === null || obj === undefined) return ''
  if (typeof obj !== 'object') return JSON.stringify(obj)
  if (Array.isArray(obj)) {
    return '[' + obj.map(item => canonicalize(item)).join(',') + ']'
  }
  const sorted = Object.keys(obj as Record<string, unknown>)
    .sort()
    .filter(key => {
      const val = (obj as Record<string, unknown>)[key]
      return val !== null && val !== undefined
    })
    .map(key => {
      const val = (obj as Record<string, unknown>)[key]
      return `${JSON.stringify(key)}:${canonicalize(val)}`
    })
  return '{' + sorted.join(',') + '}'
}
