import { useEffect, useRef, useState, type ElementType } from 'react'
import { useReducedMotion } from '../lib/useReducedMotion'

type RevealAxis = 'fade' | 'up' | 'scale' | 'left' | 'right' | 'words'

const CLASS_MAP: Record<RevealAxis, string> = {
  fade: 'reveal-fade',
  up: 'reveal',
  scale: 'reveal-scale',
  left: 'reveal-left',
  right: 'reveal-right',
  words: 'reveal-words',
}

export function ScrollReveal({
  children,
  className = '',
  delay = 0,
  as = 'div',
  axis = 'up',
  index,
}: {
  children: React.ReactNode
  className?: string
  delay?: number
  as?: 'div' | 'p' | 'article' | 'section' | 'ul' | 'li'
  axis?: RevealAxis
  /** Index within a parent stagger group; drives CSS transition-delay. */
  index?: number
}) {
  const reduce = useReducedMotion()
  const ref = useRef<HTMLDivElement>(null)
  const [visible, setVisible] = useState(reduce)
  const Tag = as as ElementType

  useEffect(() => {
    if (reduce || visible) return
    const el = ref.current
    if (!el) return

    let timer: ReturnType<typeof setTimeout> | undefined
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry?.isIntersecting) {
          timer = setTimeout(() => setVisible(true), delay * 1000)
          observer.disconnect()
        }
      },
      { threshold: 0.15, rootMargin: '0px 0px -50px 0px' },
    )

    observer.observe(el)
    return () => {
      clearTimeout(timer)
      observer.disconnect()
    }
  }, [reduce, visible, delay])

  if (reduce) {
    return <Tag className={className}>{children}</Tag>
  }

  const staggerDelay = index !== undefined ? `calc(${index} * var(--stagger-step))` : undefined

  const content =
    axis === 'words' && typeof children === 'string' ? (
      children.split(' ').map((word, i) => (
        <span
          key={i}
          className="reveal-word"
          style={{ '--word-delay': `${i * 22}ms` } as React.CSSProperties}
        >
          {word}
          {i < children.split(' ').length - 1 ? ' ' : ''}
        </span>
      ))
    ) : (
      children
    )

  return (
    <Tag
      ref={ref}
      className={`${CLASS_MAP[axis]} ${visible ? 'reveal-visible ' : ''}${className}`}
      style={{ transitionDelay: staggerDelay ?? `${delay * 1000}ms` }}
    >
      {content}
    </Tag>
  )
}

export function ScrollRevealParent({
  children,
  className,
  as = 'div',
}: {
  children: React.ReactNode
  className?: string
  as?: 'div' | 'ul' | 'section'
}) {
  const Tag = as as ElementType
  return (
    <Tag className={`reveal-stagger ${className ?? ''}`}>
      {children}
    </Tag>
  )
}
