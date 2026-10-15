import { useEffect, useRef, useState } from 'react'

/**
 * BinaryDecode — text renders as raw binary (0s/1s) and resolves into the
 * real text character-by-character as it enters the viewport. The "decompile"
 * signature effect for a reverse-engineering company.
 *
 * - The real text is visible on the very first render (and to crawlers / no-JS).
 * - prefers-reduced-motion: final text is shown immediately, no animation.
 * - Writes directly to node.textContent inside one requestAnimationFrame loop.
 * - During the decode the container is aria-hidden so screen readers do not
 *   announce the flickering binary state.
 */
export function BinaryDecode({
  text,
  className,
  as: Tag = 'span',
}: {
  text: string
  className?: string
  as?: React.ElementType
}) {
  const ref = useRef<HTMLElement>(null)
  const [inView, setInView] = useState(false)
  const [reduce, setReduce] = useState(false)
  const [done, setDone] = useState(false)

  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    setReduce(mq.matches)
    const sync = () => {
      setReduce(mq.matches)
      if (mq.matches) setDone(true)
    }
    mq.addEventListener('change', sync)

    const node = ref.current
    if (!node) return () => mq.removeEventListener('change', sync)

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry?.isIntersecting) {
          setInView(true)
          observer.disconnect()
        }
      },
      { threshold: 0.3, rootMargin: '0px' },
    )
    observer.observe(node)

    return () => {
      mq.removeEventListener('change', sync)
      observer.disconnect()
    }
  }, [])

  useEffect(() => {
    const node = ref.current
    if (!node) return

    const buildBinary = () => {
      let out = ''
      for (let i = 0; i < text.length; i++) {
        out += Math.random() < 0.5 ? '0' : '1'
      }
      return out
    }

    if (reduce) {
      node.textContent = text
      setDone(true)
      return
    }

    node.textContent = buildBinary()
    if (!inView) return

    const total = text.length
    const seedFront = Math.max(3, Math.floor(total * 0.04))
    const duration = Math.min(1800, 700 + total * 22)
    let start: number | null = null
    let raf = 0

    const frame = (t: number) => {
      if (start === null) start = t
      const p = Math.min(1, (t - start) / duration)
      const eased = 1 - Math.pow(1 - p, 3)
      const resolved = Math.floor(eased * total)

      let out = ''
      for (let i = 0; i < total; i++) {
        if (i < resolved) {
          out += text[i]
        } else if (i < resolved + seedFront) {
          out += Math.random() < 0.5 ? '0' : '1'
        } else {
          out += node.textContent?.[i] ?? '0'
        }
      }
      node.textContent = out

      if (p < 1) {
        raf = requestAnimationFrame(frame)
      } else {
        node.textContent = text
        setDone(true)
      }
    }

    raf = requestAnimationFrame(frame)
    return () => cancelAnimationFrame(raf)
  }, [inView, reduce, text])

  const decoding = !reduce && inView && !done

  return (
    <Tag
      ref={ref as React.Ref<HTMLElement>}
      className={className}
      aria-label={text}
      aria-hidden={decoding ? true : undefined}
    >
      {text}
    </Tag>
  )
}
