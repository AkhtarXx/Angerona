import { useEffect, useRef, useState } from 'react'
import { useReducedMotion } from '../lib/useReducedMotion'

/**
 * ScrollProgress — a thin bar pinned to the top of the viewport that fills
 * with the violet signal as the user scrolls down.
 *
 * Implemented without Framer Motion to keep the initial bundle small; the
 * effect is fully disabled under prefers-reduced-motion.
 */
export function ScrollProgress() {
  const reduce = useReducedMotion()
  const [progress, setProgress] = useState(0)
  const rafRef = useRef<number | null>(null)

  useEffect(() => {
    if (reduce) return

    const updateProgress = () => {
      const docHeight = document.documentElement.scrollHeight - window.innerHeight
      const p = docHeight > 0 ? window.scrollY / docHeight : 0
      setProgress(Math.min(1, Math.max(0, p)))
      rafRef.current = null
    }

    const onScroll = () => {
      if (rafRef.current !== null) return
      rafRef.current = requestAnimationFrame(updateProgress)
    }

    window.addEventListener('scroll', onScroll, { passive: true })
    updateProgress()

    return () => {
      window.removeEventListener('scroll', onScroll)
      if (rafRef.current !== null) cancelAnimationFrame(rafRef.current)
    }
  }, [reduce])

  if (reduce) return null

  return (
    <div
      className="fixed inset-x-0 top-0 z-[60] h-[2px] origin-left bg-signal-violet/80"
      style={{ transform: `scaleX(${progress})` }}
      aria-hidden
    />
  )
}
