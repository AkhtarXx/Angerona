import { Section } from '../ui/Section'
import { SectionHeading } from '../SectionHeading'
import { ScrollReveal, ScrollRevealParent } from '../ScrollReveal'
import { VolumetricCard } from '../VolumetricCard'
import { SectionGlow } from '../SectionGlow'

const AUDIENCES = [
  {
    role: 'Product security teams',
    copy: 'Triage vendor firmware and third-party binaries for vulnerabilities before they ship in your stack.',
  },
  {
    role: 'Incident responders',
    copy: 'Trace an unknown sample to its entry-to-sink path and confirm whether attacker input can reach a sensitive sink.',
  },
  {
    role: 'Blockchain security',
    copy: 'Audit Solana BPF and other on-chain bytecode where source may be absent, inaccurate, or unverifiable.',
  },
  {
    role: 'Malware analysts',
    copy: 'Recover logic from stripped samples and get an evidence-bound report instead of a best guess.',
  },
]

export default function UseCases() {
  return (
    <Section id="use-cases">
      <SectionGlow x="right" y="center" color="violet" size="md" />
      <ScrollReveal>
        <SectionHeading className="mb-16">Who we work with</SectionHeading>
      </ScrollReveal>

      <ScrollRevealParent
        as="div"
        className="grid grid-cols-1 gap-5 md:grid-cols-2"
      >
        {AUDIENCES.map((a, i) => (
          <ScrollReveal key={a.role} axis={i % 2 === 0 ? 'left' : 'right'} as="div" index={i}>
            <VolumetricCard
              className="h-full rounded-2xl"
              frontClassName="h-full rounded-2xl liquid-glass"
            >
              <div className="h-full p-6 sm:p-8" >
                <h3 className="text-[19px] font-medium text-foreground sm:text-[21px]">
                  {a.role}
                </h3>
                <p className="mt-3 max-w-[420px] text-[15px] leading-[1.65] text-hero-sub">
                  {a.copy}
                </p>
              </div>
            </VolumetricCard>
          </ScrollReveal>
        ))}
      </ScrollRevealParent>
    </Section>
  )
}
