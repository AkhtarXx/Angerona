import { useEffect, useRef, useState } from 'react'
import { useReducedMotion } from '../lib/useReducedMotion'

/**
 * Terminal — a self-running mock CLI that types a reverse-engineering command
 * and prints its output. Designed for credibility, not theatre.
 *
 * - Final state is rendered as static HTML so SSR / no-JS users see content.
 * - Animation pauses on hover/focus so users can read.
 * - Disabled immediately under prefers-reduced-motion.
 */
type LineTone = 'command' | 'info' | 'ok' | 'warn'

const BOOT_LINES: { text: string; indent: number; delay?: number; tone?: LineTone }[] = [
  { text: '$ angerona run ./authorized-target --engine configured', indent: 0, tone: 'command' },
  { text: '[analysis] extracting reviewable binary evidence', indent: 2, delay: 300, tone: 'info' },
  { text: '[recovery] building a normalized analysis workspace', indent: 2, delay: 600, tone: 'info' },
  { text: '[review] evaluating candidate security claims', indent: 2, delay: 900, tone: 'info' },
  { text: '[evidence] recording available verification status', indent: 2, delay: 1200, tone: 'ok' },
  { text: '[report] review package ready for analyst validation', indent: 2, delay: 1500, tone: 'warn' },
  { text: '$ _', indent: 0, delay: 1800, tone: 'command' },
]

export default function Terminal({ className }: { className?: string }) {
  const reduce = useReducedMotion()
  const [visible, setVisible] = useState(reduce ? BOOT_LINES.length : 0)
  const [paused, setPaused] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (reduce) {
      setVisible(BOOT_LINES.length)
      return
    }
    if (paused || visible >= BOOT_LINES.length) return

    const next = BOOT_LINES[visible]
    const wait = next.delay ?? 180
    const timer = setTimeout(() => {
      setVisible((v) => v + 1)
    }, wait)

    return () => clearTimeout(timer)
  }, [visible, paused, reduce])

  // Keep the terminal scrolled to the bottom, but batch the layout read/write
  // in a requestAnimationFrame so it does not force synchronous reflow.
  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    let raf: number | null = null
    const scrollToBottom = () => {
      raf = null
      el.scrollTop = el.scrollHeight
    }
    raf = requestAnimationFrame(scrollToBottom)
    return () => {
      if (raf !== null) cancelAnimationFrame(raf)
    }
  }, [visible])

  const displayed = BOOT_LINES.slice(0, visible)

  return (
    <div
      className={`rounded-[var(--radius-cards)] border border-foreground/10 bg-background-soft/80 backdrop-blur-none md:backdrop-blur-[2px] font-mono shadow-xl ${className}`}
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      onFocus={() => setPaused(true)}
      onBlur={() => setPaused(false)}
      role="region"
      aria-label="Angerona command-line demo"
    >
      {/* Window chrome */}
      <div className="flex items-center gap-2 border-b border-foreground/10 px-4 py-3">
        <span className="h-3 w-3 rounded-full bg-foreground/15" aria-hidden />
        <span className="h-3 w-3 rounded-full bg-foreground/15" aria-hidden />
        <span className="h-3 w-3 rounded-full bg-foreground/15" aria-hidden />
        <span className="ml-2 text-[11px] text-foreground/40">angerona — zsh</span>
      </div>

      {/* Terminal body */}
      <div
        ref={containerRef}
        className="max-h-[320px] overflow-y-auto p-4 text-[13px] leading-[1.6] sm:p-5 sm:text-[14px]"
      >
        {displayed.map((line, i) => (
          <div
            key={i}
            className="whitespace-pre-wrap break-words"
            style={{ paddingLeft: `${line.indent * 12}px` }}
          >
            <TerminalLine text={line.text} tone={line.tone} isCursor={i === displayed.length - 1 && !reduce && visible < BOOT_LINES.length} />
          </div>
        ))}
      </div>
    </div>
  )
}

function TerminalLine({
  text,
  tone = 'info',
  isCursor,
}: {
  text: string
  tone?: LineTone
  isCursor?: boolean
}) {
  const color =
    tone === 'command'
      ? 'text-foreground'
      : tone === 'ok'
        ? 'text-emerald-400/90'
        : tone === 'warn'
          ? 'text-amber-400/90'
          : 'text-signal-violet/80'

  return (
    <span className={color}>
      {text}
      {isCursor && <span className="ml-0.5 inline-block h-4 w-2 animate-pulse bg-foreground/60 align-text-bottom" aria-hidden />}
    </span>
  )
}
