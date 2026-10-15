import { useEffect, useRef, useState } from 'react'

/**
 * useInViewOnce — a lightweight native IntersectionObserver hook.
 *
 * Returns true once the element has entered the viewport by `threshold`.
 * Cheaper than per-component motion observers for pages with many reveals.
 */
export function useInViewOnce({
  threshold = 0.15,
  rootMargin = '0px 0px -50px 0px',
}: {
  threshold?: number
  rootMargin?: string
} = {}) {
  const ref = useRef<HTMLElement>(null)
  const [inView, setInView] = useState(false)

  useEffect(() => {
    const el = ref.current
    if (!el || inView) return

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry?.isIntersecting) {
          setInView(true)
          observer.disconnect()
        }
      },
      { threshold, rootMargin },
    )

    observer.observe(el)
    return () => observer.disconnect()
  }, [inView, threshold, rootMargin])

  return { ref, inView }
}
