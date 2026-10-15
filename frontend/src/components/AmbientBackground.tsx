/**
 * AmbientBackground — a single directional light and a grain texture.
 *
 * No video, no drifting blobs, no candy aurora. The canvas is intentionally
 * quiet so the subject's artifacts (the code panel and graph) become the focus.
 */
export function AmbientBackground() {
  return <div className="bg-atmosphere" aria-hidden />
}
