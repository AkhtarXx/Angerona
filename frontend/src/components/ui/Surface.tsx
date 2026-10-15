import { cn } from '../../lib/cn'

type SurfaceProps = {
  variant?: 'default' | 'panel' | 'accent' | 'glass'
  padding?: 'none' | 'sm' | 'md' | 'lg'
  children: React.ReactNode
  className?: string
} & React.HTMLAttributes<HTMLDivElement>

/**
 * Surface — panels tuned to the hero's deep blue-purple canvas.
 * `glass` is a quiet translucent card that echoes the hero's liquid-glass
 * without copying its icon-chip treatment.
 */
export function Surface({
  variant = 'default',
  padding = 'md',
  children,
  className,
  ...rest
}: SurfaceProps) {
  const paddings = {
    none: '',
    sm: 'p-5',
    md: 'p-6',
    lg: 'p-8',
  }

  const variants = {
    default: 'rounded-2xl bg-foreground/[0.03] border border-foreground/10',
    panel: 'rounded-2xl bg-void',
    accent: 'rounded-2xl bg-signal-violet text-almost-white',
    glass:
      'rounded-2xl bg-white/[0.02] border border-white/10 backdrop-blur-sm',
  }

  return (
    <div className={cn(variants[variant], paddings[padding], className)} {...rest}>
      {children}
    </div>
  )
}
