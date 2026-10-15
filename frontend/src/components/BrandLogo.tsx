import { cn } from '../lib/cn'

type BrandLogoProps = {
  className?: string
  markClassName?: string
  wordmarkClassName?: string
  compact?: boolean
}

export function BrandLogo({
  className,
  markClassName,
  wordmarkClassName,
  compact = false,
}: BrandLogoProps) {
  return (
    <span className={cn('inline-flex items-center gap-3 text-foreground', className)}>
      <span
        className={cn(
          'relative grid h-9 w-9 place-items-center overflow-hidden rounded-[10px] border border-white/12 bg-white/[0.03] shadow-[inset_0_1px_0_rgba(255,255,255,0.18),0_0_28px_rgba(61,225,232,0.12)]',
          markClassName,
        )}
        aria-hidden="true"
      >
        <svg
          viewBox="0 0 40 40"
          className="h-full w-full"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <linearGradient id="angerona-mark-stroke" x1="8" y1="32" x2="32" y2="8" gradientUnits="userSpaceOnUse">
              <stop stopColor="#3DE1E8" />
              <stop offset="0.46" stopColor="#B873FF" />
              <stop offset="1" stopColor="#F5B73D" />
            </linearGradient>
            <radialGradient id="angerona-mark-glow" cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse" gradientTransform="translate(20 19) rotate(90) scale(20)">
              <stop stopColor="#3DE1E8" stopOpacity="0.18" />
              <stop offset="1" stopColor="#080418" stopOpacity="0" />
            </radialGradient>
          </defs>
          <rect width="40" height="40" rx="10" fill="url(#angerona-mark-glow)" />
          <path
            d="M10 29.5L18.1 10.8C18.8 9.2 21.2 9.2 21.9 10.8L30 29.5"
            stroke="url(#angerona-mark-stroke)"
            strokeWidth="3"
            strokeLinecap="round"
          />
          <path
            d="M14.3 23.2H25.7"
            stroke="#F6F4F0"
            strokeOpacity="0.9"
            strokeWidth="2.2"
            strokeLinecap="round"
          />
          <path
            d="M25.8 14.2H31.6M31.6 14.2V20"
            stroke="#3DE1E8"
            strokeOpacity="0.78"
            strokeWidth="1.4"
            strokeLinecap="round"
          />
          <circle cx="31.6" cy="20" r="2" fill="#3DE1E8" />
          <circle cx="8.4" cy="28.7" r="1.8" fill="#F5B73D" />
        </svg>
      </span>

      {!compact && (
        <span className={cn('leading-none', wordmarkClassName)}>
          <span
            className="block font-medium text-[18px]"
            style={{ fontFamily: 'var(--font-general)', letterSpacing: '0' }}
          >
            Angerona<span className="text-signal-cyan">Labs</span>
          </span>
          <span className="mt-1 hidden text-[10px] font-medium uppercase tracking-[0.18em] text-foreground/42 sm:block">
            Security Research
          </span>
        </span>
      )}
    </span>
  )
}
