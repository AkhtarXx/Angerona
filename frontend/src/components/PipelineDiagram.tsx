import { useEffect, useRef, useState } from 'react'
import { useReducedMotion } from '../lib/useReducedMotion'
import { useScrollState } from '../lib/useScrollState'

const STEPS = [
  { id: 'target', label: 'Target', sub: 'Authorized input' },
  { id: 'analyze', label: 'Analyze', sub: 'Configured engine' },
  { id: 'recover', label: 'Recover', sub: 'Local evidence' },
  { id: 'review', label: 'Review', sub: 'Bounded analysis' },
  { id: 'verify', label: 'Check', sub: 'Evidence status' },
  { id: 'report', label: 'Report', sub: 'Review package' },
]

export function PipelineDiagram({ className }: { className?: string }) {
  const reduce = useReducedMotion()
  const { y, viewportProgress: scrollProgress } = useScrollState()
  const [progress, setProgress] = useState(reduce ? 1 : 0)
  const [visible, setVisible] = useState(false)
  const [isMobile, setIsMobile] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const rafRef = useRef<number | null>(null)

  useEffect(() => {
    const mobile = typeof window !== 'undefined' && window.matchMedia('(max-width: 1023px)').matches
    setIsMobile(mobile)
    if (reduce || mobile) {
      setProgress(1)
      setVisible(true)
    }
  }, [reduce])

  useEffect(() => {
    if (reduce || isMobile) return

    const el = ref.current
    if (!el) return

    const syncProgress = () => {
      rafRef.current = null
      const rect = el.getBoundingClientRect()
      const windowHeight = window.innerHeight
      // Scrub from when the diagram enters 65% of viewport until it reaches 15%.
      const start = windowHeight * 0.65
      const end = windowHeight * 0.15
      const raw = (start - rect.top) / (start - end)
      const clamped = Math.min(1, Math.max(0, raw))
      setProgress(clamped)
      setVisible(clamped > 0)
    }

    if (rafRef.current === null) {
      rafRef.current = requestAnimationFrame(syncProgress)
    }

    return () => {
      if (rafRef.current !== null) {
        cancelAnimationFrame(rafRef.current)
        rafRef.current = null
      }
    }
    // Re-run whenever shared scroll state changes; RAF gate prevents extra work.
  }, [scrollProgress, y, reduce, isMobile])

  const activeIndex = Math.min(STEPS.length - 1, Math.floor(progress * STEPS.length))

  if (isMobile) {
    return (
      <div className={`w-full ${className}`}>
        <div className="mobile-pipeline-grid relative grid grid-cols-2 gap-4">
          <div
            className="absolute top-0 bottom-0 left-1/2 w-px -translate-x-1/2 bg-foreground/10"
            aria-hidden
          />
          <div
            className="absolute top-0 left-1/2 w-px -translate-x-1/2 bg-gradient-to-b from-signal-violet to-signal-cyan"
            aria-hidden
            style={{
              height: `calc(${progress * 100}% - 24px)`,
              opacity: visible ? 1 : 0,
              transition: reduce ? 'none' : 'opacity 0.5s ease',
            }}
          />
          {STEPS.map((step, i) => (
            <PipelineStepMobile
              key={step.id}
              step={step}
              index={i}
              active={i <= activeIndex}
              visible={visible && i <= activeIndex + 1}
            />
          ))}
        </div>
      </div>
    )
  }

  return (
    <div ref={ref} className={`w-full overflow-visible ${className}`}>
      <div className="relative min-w-[680px] px-2 py-6">
        <div
          className="absolute top-1/2 left-[calc(16.67%-24px)] right-[calc(16.67%-24px)] h-px -translate-y-1/2 bg-foreground/10"
          aria-hidden
        />
        <ProgressLine progress={progress} visible={visible} reduce={reduce} />
        <div className="relative grid grid-cols-6 gap-2" style={{ '--active-index': activeIndex } as React.CSSProperties}>
          {STEPS.map((step, i) => (
            <PipelineStep
              key={step.id}
              step={step}
              index={i}
              active={i <= activeIndex}
              visible={visible}
            />
          ))}
        </div>
      </div>
    </div>
  )
}

function ProgressLine({
  progress,
  visible,
  reduce,
}: {
  progress: number
  visible: boolean
  reduce: boolean
}) {
  return (
    <div
      className="absolute top-1/2 left-[calc(16.67%-24px)] h-px -translate-y-1/2 bg-gradient-to-r from-signal-violet to-signal-cyan"
      aria-hidden
      style={{
        width: `calc(${progress * 100}% - ${32 * progress}px)`,
        opacity: visible ? 1 : 0,
        transition: reduce ? 'none' : 'opacity 0.5s ease',
      }}
    />
  )
}

function PipelineStep({
  step,
  index,
  active,
  visible,
}: {
  step: (typeof STEPS)[number]
  index: number
  active: boolean
  visible: boolean
}) {
  return (
    <div
      className="group flex flex-col items-center text-center transition-all duration-[500ms] ease-[cubic-bezier(0.16,1,1,0.3)]"
      style={{
        opacity: visible ? 1 : 0,
        transform: visible ? 'translateY(0)' : 'translateY(12px)',
        transitionDelay: `${index * 80}ms`,
      }}
    >
      <div
        className={`relative z-10 flex h-12 w-12 items-center justify-center rounded-full border transition-all duration-500 sm:h-14 sm:w-14 ${
          active
            ? 'pipeline-step-active border-signal-violet/60 bg-signal-violet/10 text-foreground shadow-[0_0_0_6px_rgba(154,77,255,0.06)]'
            : 'border-foreground/15 bg-background-soft/80 text-foreground/60 group-hover:border-foreground/25'
        }`}
      >
        <span className="font-mono text-[12px] sm:text-[13px]">{String(index + 1).padStart(2, '0')}</span>
      </div>
      <div className="mt-3">
        <div className={`text-[13px] font-medium sm:text-[14px] ${active ? 'text-foreground' : 'text-foreground/70'}`}>
          {step.label}
        </div>
        <div className="mt-0.5 text-[11px] text-foreground/45 sm:text-[12px]">{step.sub}</div>
      </div>
    </div>
  )
}

function PipelineStepMobile({
  step,
  index,
  active,
  visible,
}: {
  step: (typeof STEPS)[number]
  index: number
  active: boolean
  visible: boolean
}) {
  return (
    <div
      className="group flex items-start gap-3 rounded-xl border border-foreground/10 bg-foreground/[0.03] p-4 transition-all duration-500"
      style={{
        opacity: visible ? 1 : 0,
        transform: visible ? 'translateY(0)' : 'translateY(10px)',
        transitionDelay: `${index * 60}ms`,
      }}
    >
      <div
        className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-full border transition-all duration-500 ${
          active
            ? 'border-signal-violet/60 bg-signal-violet/10 text-foreground shadow-[0_0_0_4px_rgba(154,77,255,0.06)]'
            : 'border-foreground/15 bg-background-soft/80 text-foreground/60'
        }`}
      >
        <span className="font-mono text-[11px]">{String(index + 1).padStart(2, '0')}</span>
      </div>
      <div>
        <div className={`text-[14px] font-medium ${active ? 'text-foreground' : 'text-foreground/70'}`}>
          {step.label}
        </div>
        <div className="mt-0.5 text-[12px] text-foreground/45">{step.sub}</div>
      </div>
    </div>
  )
}
