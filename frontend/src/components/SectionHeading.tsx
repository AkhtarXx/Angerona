import { BinaryDecode } from './BinaryDecode'

/**
 * SectionHeading — large, left-aligned, General Sans display. The heading
 * text renders as raw binary and decodes into the real words as the section
 * enters the viewport — the "decompile" signature effect, tied to the page's
 * reverse-engineering theme.
 */
export function SectionHeading({
  children,
  className,
  eyebrow,
}: {
  children: string
  className?: string
  eyebrow?: string
}) {
  return (
    <div className={className}>
      {eyebrow && (
        <span className="mb-3 block font-mono text-[11px] uppercase tracking-[0.14em] text-foreground/45">
          {eyebrow}
        </span>
      )}
      <h2
        className="font-normal leading-[1.08] text-foreground"
        style={{
          fontFamily: 'var(--font-general)',
          fontSize: 'clamp(30px, 5vw, 56px)',
          letterSpacing: '-0.025em',
        }}
      >
        <BinaryDecode text={children} />
      </h2>
    </div>
  )
}
