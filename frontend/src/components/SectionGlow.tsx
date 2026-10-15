import { cn } from '../lib/cn'
import { useScrollParallax } from '../lib/useScrollParallax'

interface SectionGlowProps {
  /** Position of the glow on the horizontal axis. */
  x?: 'left' | 'center' | 'right'
  /** Vertical position of the glow. */
  y?: 'top' | 'center' | 'bottom'
  /** Glow color from the theme. */
  color?: 'violet' | 'indigo' | 'faint'
  /** Size of the blurred blob. */
  size?: 'sm' | 'md' | 'lg'
  /** Subtle parallax drift on desktop. 0.03-0.06 is usually enough. */
  parallaxRate?: number
  className?: string
}

/**
 * SectionGlow — a single static blurred light blob placed behind a section.
 *
 * Used to eliminate the flat-black void between the hero video and the deep
 * canvas gradient. No animation, no performance cost, just depth.
 */
export function SectionGlow({
  x = 'center',
  y = 'center',
  color = 'violet',
  size = 'md',
  parallaxRate,
  className,
}: SectionGlowProps) {
  const parallaxY = useScrollParallax(parallaxRate ?? 0, parallaxRate === undefined)
  const leftMap = {
    left: 'left-0',
    center: 'left-1/2',
    right: 'right-0',
  } as const

  const topMap = {
    top: 'top-0',
    center: 'top-1/2',
    bottom: 'bottom-0',
  } as const

  const xOffset: Record<NonNullable<SectionGlowProps['x']>, string> = {
    left: '-33.33%',
    center: '-50%',
    right: '33.33%',
  }

  const yOffset: Record<NonNullable<SectionGlowProps['y']>, string> = {
    top: '-33.33%',
    center: '-50%',
    bottom: '33.33%',
  }

  const sizeClass = {
    sm: 'w-[320px] h-[220px]',
    md: 'w-[520px] h-[360px]',
    lg: 'w-[760px] h-[480px]',
  }[size]

  const colorClass = {
    violet: 'bg-purple-600/[0.06]',
    indigo: 'bg-indigo-600/[0.05]',
    faint: 'bg-violet-400/[0.03]',
  }[color]

  const baseTransform = `translate(${xOffset[x]}, ${yOffset[y]})`
  const styleTransform = parallaxRate
    ? `${baseTransform} translateY(${parallaxY}px)`
    : baseTransform

  return (
    <div
      className={cn(
        'pointer-events-none absolute -z-10 overflow-hidden',
        leftMap[x],
        topMap[y],
        sizeClass,
        colorClass,
        'rounded-full blur-[60px] md:blur-[120px]',
        className,
      )}
      style={{ transform: styleTransform }}
      aria-hidden
    />
  )
}
