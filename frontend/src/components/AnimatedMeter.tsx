import { useEffect, useRef, useState } from 'react'

export function AnimatedMeter({
  value,
  className,
}: {
  value: number
  className?: string
}) {
  const ref = useRef<HTMLDivElement>(null)
  const [active, setActive] = useState(false)
  const [reduce, setReduce] = useState(false)
  const pct = Math.round(value * 100)

  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    setReduce(mq.matches)
    const sync = () => setReduce(mq.matches)
    mq.addEventListener('change', sync)

    const el = ref.current
    if (!el) return () => mq.removeEventListener('change', sync)

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry?.isIntersecting) {
          setActive(true)
          observer.disconnect()
        }
      },
      { threshold: 0.5 },
    )
    observer.observe(el)
    return () => {
      mq.removeEventListener('change', sync)
      observer.disconnect()
    }
  }, [])

  return (
    <div ref={ref} className={className}>
      <div className="h-1.5 w-24 overflow-hidden rounded-full bg-foreground/10">
        <div
          className="h-full origin-left rounded-full bg-signal-violet/70 transition-transform duration-700 ease-[cubic-bezier(0.16,1,1,0.3)]"
          style={{ transform: `scaleX(${active || reduce ? pct / 100 : 0})` }}
        />
      </div>
    </div>
  )
}
