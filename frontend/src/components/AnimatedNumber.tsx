import { useEffect, useRef, useState } from 'react'

export function AnimatedNumber({
  value,
  suffix = '',
  className,
}: {
  value: number
  suffix?: string
  className?: string
}) {
  const ref = useRef<HTMLSpanElement>(null)
  const [display, setDisplay] = useState(value)
  const [reduce, setReduce] = useState(false)
  const hasAnimated = useRef(false)

  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    setReduce(mq.matches)
    const sync = () => setReduce(mq.matches)
    mq.addEventListener('change', sync)

    const el = ref.current
    if (!el) return () => mq.removeEventListener('change', sync)

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (!entry?.isIntersecting || hasAnimated.current) return
        hasAnimated.current = true
        if (mq.matches) return

        const duration = 1200
        const start = performance.now()
        let raf = 0

        const frame = (t: number) => {
          const p = Math.min(1, (t - start) / duration)
          const eased = 1 - Math.pow(1 - p, 3)
          setDisplay(Math.floor(eased * value))
          if (p < 1) {
            raf = requestAnimationFrame(frame)
          } else {
            setDisplay(value)
          }
        }

        raf = requestAnimationFrame(frame)
        return () => cancelAnimationFrame(raf)
      },
      { threshold: 0.5 },
    )

    observer.observe(el)
    return () => {
      mq.removeEventListener('change', sync)
      observer.disconnect()
    }
  }, [value, reduce])

  return (
    <span ref={ref} className={className} aria-label={`${value}${suffix}`}>
      {display}
      {suffix}
    </span>
  )
}
