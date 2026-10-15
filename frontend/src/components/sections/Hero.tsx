import { useEffect, useRef } from 'react'
import { Button } from '../ui/Button'
import { ScrollReveal } from '../ScrollReveal'
import { useReducedMotion } from '../../lib/useReducedMotion'
import { useScrollState } from '../../lib/useScrollState'

const ARCHITECTURES = [
  'Native binaries',
  'Embedded targets',
  'Custom runtimes',
  'Program analysis',
]

export default function Hero() {
  const reduce = useReducedMotion()
  const animate = !reduce
  const { viewportProgress: scroll } = useScrollState()

  return (
    <section
      id="top"
      className="relative flex min-h-screen flex-col items-center overflow-visible bg-background"
    >
      <div
        className="absolute inset-0 bg-[radial-gradient(circle_at_50%_30%,rgba(124,58,237,0.22),transparent_48%),linear-gradient(to_bottom,rgba(88,28,135,0.22),var(--color-background))]"
        aria-hidden
      />

      <div
        className="pointer-events-none absolute inset-0 z-[1] hidden md:block"
        style={{
          background:
            'radial-gradient(circle at center, transparent 0%, hsl(260 87% 3% / 0.55) 70%, hsl(260 87% 3% / 0.75) 100%)',
        }}
        aria-hidden
      />

      <div
        className="pointer-events-none absolute top-1/2 left-1/2 z-[1] h-[420px] w-[820px] -translate-x-1/2 -translate-y-1/2 bg-background opacity-80 blur-[100px] hidden md:block"
        style={{
          opacity: Math.max(0, 0.75 * (1 - scroll * 0.7)),
          transform: `translate(-50%, -50%) scale(${1 + scroll * 0.08})`,
        }}
      />

      <div
        className={`relative z-10 flex w-full flex-1 flex-col pt-20 ${
          animate ? 'hero-animate' : ''
        }`}
        style={{
          opacity: Math.max(0, 1 - scroll * 0.7),
          transform: `translateY(${scroll * -40}px)`,
        }}
      >
        <div className="flex flex-1 flex-col items-center justify-center px-6">
          <div className="w-full max-w-[1100px] text-center">
            <div className="hero-item" style={{ '--hero-index': 0 } as React.CSSProperties}>
              <a
                href="#top"
                className="inline-block text-[14px] tracking-[0.02em] text-foreground/50"
              >
                angeronalabs / security research
              </a>
            </div>

            <div className="hero-item" style={{ '--hero-index': 1 } as React.CSSProperties}>
              <h1
                className="hero-headline mx-auto mt-6 max-w-[1000px] font-normal text-foreground"
                style={{
                  fontFamily: 'var(--font-general)',
                  fontSize: 'clamp(40px, 8vw, 110px)',
                  lineHeight: 1.02,
                  letterSpacing: '-0.024em',
                }}
              >
                <span
                  className="hero-h1-line block text-foreground/40"
                  style={{
                    fontSize: 'clamp(22px, 4vw, 40px)',
                    letterSpacing: '-0.01em',
                    fontWeight: 300,
                    lineHeight: 1.1,
                    marginBottom: '0.35em',
                  }}
                >
                  Accelerating
                </span>
                <span className="hero-h1-line block bg-gradient-to-r from-signal-violet via-[#c084fc] to-signal-cyan bg-clip-text text-transparent">
                  Reverse Engineering
                </span>
                <span
                  className="hero-h1-line block text-foreground/85"
                  style={{ fontSize: 'clamp(30px, 5.2vw, 62px)', letterSpacing: '-0.02em' }}
                >
                  Through Artificial Intelligence
                </span>
              </h1>
            </div>

            <div className="hero-item" style={{ '--hero-index': 2 } as React.CSSProperties}>
              <ScrollReveal
                as="p"
                axis="words"
                className="mx-auto mt-8 max-w-[660px] text-[17px] leading-[1.6] text-hero-sub sm:text-[18px]"
              >
                Local analysis and optional bounded agents help your team investigate
                authorized binaries while keeping claims connected to reviewable evidence.
              </ScrollReveal>
            </div>

            <div className="hero-item" style={{ '--hero-index': 3 } as React.CSSProperties}>
              <div className="mt-10 flex flex-wrap items-center justify-center gap-4">
                <Button variant="primary" size="lg" href="#demo">
                  Talk to us
                </Button>
                <Button variant="heroSecondary" size="lg" href="#approach">
                  See how we work
                </Button>
              </div>
            </div>
          </div>
        </div>

        <div className="hero-item" style={{ '--hero-index': 4 } as React.CSSProperties}>
          <LogoMarquee />
        </div>
      </div>

      <div className="hero-seam-fade" aria-hidden />
    </section>
  )
}

function LogoMarquee() {
  const items = [...ARCHITECTURES, ...ARCHITECTURES]
  const trackRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (typeof window === 'undefined') return
    if (!window.matchMedia('(max-width: 768px)').matches) return

    const track = trackRef.current
    if (!track) return

    track.style.animationPlayState = 'paused'
    const observer = new IntersectionObserver(
      ([entry]) => {
        track.style.animationPlayState = entry?.isIntersecting ? 'running' : 'paused'
      },
      { threshold: 0 }
    )
    observer.observe(track)

    return () => observer.disconnect()
  }, [])

  return (
    <div className="mx-auto w-full max-w-5xl px-8 pb-8">
      <div className="relative overflow-hidden py-4">
        <div ref={trackRef} className="marquee-track items-center gap-10">
          {items.map((name, i) => (
            <div key={`${name}-${i}`} className="flex items-center gap-2">
              <div className="liquid-glass flex h-5 w-5 items-center justify-center rounded-md">
                <span className="text-[9px] font-semibold text-foreground">{name.split(' ')[0][0]}</span>
              </div>
              <span className="text-[14px] font-medium text-foreground/90">{name}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
