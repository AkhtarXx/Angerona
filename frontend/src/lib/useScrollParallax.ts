import { useEffect, useState } from 'react'
import { useReducedMotion } from './useReducedMotion'

/**
 * useScrollParallax — applies a subtle GPU-only translateY based on scroll.
 * Disabled on mobile and under reduced motion. Uses rAF-throttled scroll.
 */
export function useScrollParallax(rate: number, disabled = false) {
  const reduce = useReducedMotion()
  const [y, setY] = useState(0)
  const enabled = !reduce && !disabled

  useEffect(() => {
    if (!enabled || typeof window === 'undefined') return

    const isDesktop = window.matchMedia('(min-width: 769px)').matches
    if (!isDesktop) return

    let raf: number | null = null
    const onScroll = () => {
      if (raf !== null) return
      raf = requestAnimationFrame(() => {
        const center = window.innerHeight / 2
        setY((window.scrollY - center) * rate)
        raf = null
      })
    }

    window.addEventListener('scroll', onScroll, { passive: true })
    return () => {
      window.removeEventListener('scroll', onScroll)
      if (raf !== null) cancelAnimationFrame(raf)
    }
  }, [enabled, rate])

  return y
}
