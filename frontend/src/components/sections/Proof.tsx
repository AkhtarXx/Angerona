import { Section } from '../ui/Section'
import { SectionHeading } from '../SectionHeading'
import { ScrollReveal, ScrollRevealParent } from '../ScrollReveal'
import { AnimatedNumber } from '../AnimatedNumber'

const PROOF = [
  {
    value: 2,
    suffix: '',
    label: 'analysis engines',
    note: 'IDA Pro · Ghidra',
  },
  {
    value: 500,
    suffix: '+',
    label: 'regression tests',
    note: 'local backend suite',
  },
  {
    value: 4,
    suffix: '',
    label: 'core verification layers',
    note: 'claims · capabilities · structure · behavior',
  },
]

export default function Proof() {
  return (
    <Section id="proof" className="py-16 sm:py-20">
      <ScrollReveal>
        <div className="border-t border-b border-foreground/10 py-12 sm:py-14">
          <SectionHeading className="mb-12">Who we are</SectionHeading>
          <ScrollRevealParent
            as="div"
            className="grid grid-cols-1 gap-8 sm:grid-cols-3 sm:gap-6"
          >
            {PROOF.map((p, i) => (
              <ScrollReveal key={p.label} axis="scale" as="div" index={i}>
                <div className="flex flex-col gap-2">
                  <span
                    className="bg-gradient-to-r from-foreground to-signal-violet bg-clip-text font-mono text-transparent"
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: 'clamp(44px, 5vw, 68px)',
                      lineHeight: 1,
                      letterSpacing: '-0.04em',
                    }}
                  >
                    <AnimatedNumber value={p.value} suffix={p.suffix} />
                  </span>
                  <span className="text-[15px] font-medium text-foreground">{p.label}</span>
                  <span className="text-[13px] text-foreground/50">{p.note}</span>
                </div>
              </ScrollReveal>
            ))}
          </ScrollRevealParent>
        </div>
      </ScrollReveal>
    </Section>
  )
}
