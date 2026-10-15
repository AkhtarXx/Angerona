import { cn } from '../../lib/cn'

/**
 * Button — flat, intentional, no glow and no hover lift.
 *
 * Primary: a solid violet fill; the action speaks for itself.
 * Ghost: a tonal, darker fill; treated as a quiet secondary action.
 */
type ButtonProps = {
  variant?: 'primary' | 'ghost' | 'heroSecondary'
  size?: 'md' | 'lg'
  href?: string
  type?: 'button' | 'submit'
  disabled?: boolean
  children: React.ReactNode
  className?: string
} & (React.AnchorHTMLAttributes<HTMLAnchorElement> | React.ButtonHTMLAttributes<HTMLButtonElement>)

export function Button(props: ButtonProps) {
  const { variant = 'primary', size = 'md', href, type = 'button', disabled, children, className, ...rest } = props

  const base =
    'inline-flex items-center justify-center gap-2 font-medium transition-colors duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-signal-violet/50'

  const sizes = {
    md: 'text-[14px] px-5 py-2.5 rounded-full',
    lg: 'text-[15px] px-6 py-3.5 rounded-full',
  }

  const variants = {
    primary:
      'relative overflow-hidden bg-signal-violet text-almost-white hover:bg-signal-violet-dim disabled:bg-graphite disabled:text-steel shadow-[0_0_0_1px_rgba(154,77,255,0.3)] hover:shadow-[0_8px_24px_-8px_rgba(154,77,255,0.45)]',
    ghost:
      'bg-iron text-almost-white hover:text-white hover:bg-white/10 disabled:bg-graphite disabled:text-steel',
    heroSecondary:
      'rounded-full border border-foreground/20 bg-foreground/5 text-foreground hover:bg-foreground/10 hover:border-foreground/30 disabled:bg-transparent disabled:text-steel',
  }

  const classes = cn(base, sizes[size], variants[variant], className)

  if (disabled) {
    return (
      <span className={classes} aria-disabled="true">
        {children}
      </span>
    )
  }

  if (href) {
    return (
      <a href={href} className={classes} {...(rest as React.AnchorHTMLAttributes<HTMLAnchorElement>)}>
        {children}
      </a>
    )
  }

  return (
    <button type={type} className={classes} {...(rest as React.ButtonHTMLAttributes<HTMLButtonElement>)}>
      {children}
    </button>
  )
}
