import { Section } from '../ui/Section'
import { SectionHeading } from '../SectionHeading'
import { ScrollReveal, ScrollRevealParent } from '../ScrollReveal'
import { VolumetricCard } from '../VolumetricCard'
import { SectionGlow } from '../SectionGlow'

const PRINCIPLES = [
  { title: 'Local-first deployment', copy: 'Engines and workspaces run in your environment; air-gapped use requires local models and no-network configuration.' },
  { title: 'Evidence before claims', copy: 'Findings retain their evidence and verification status for review.' },
  { title: 'Audit-ready trails', copy: 'Major analysis steps and artifacts are written to a local run workspace.' },
]

const OPERATING = [
  { title: 'Untrusted by default', copy: 'We treat the binary and all tool output as untrusted data, not ground truth.' },
  { title: 'Fail closed', copy: 'Requested isolation and strict verification controls fail closed.' },
  { title: 'Bound provenance', copy: 'Every artifact is bound to its source binary; synthetic evidence is labeled.' },
  { title: 'Human review, machine evidence', copy: 'Our researchers direct the work; agents produce reproducible evidence.' },
]

export default function Security() {
  return (
    <Section id="security">
      <SectionGlow x="center" y="top" color="indigo" size="md" />
      <ScrollReveal>
        <SectionHeading className="mb-16">How we operate</SectionHeading>
      </ScrollReveal>

      <ScrollRevealParent
        as="div"
        className="grid grid-cols-1 gap-5 sm:grid-cols-3"
      >
        {PRINCIPLES.map((p, i) => (
          <ScrollReveal key={p.title} axis="scale" as="div" index={i}>
            <VolumetricCard
              className="h-full rounded-2xl"
              frontClassName="h-full rounded-2xl liquid-glass"
            >
              <div className="h-full p-6">
                <h3 className="text-[17px] font-medium text-foreground">{p.title}</h3>
                <p className="mt-2 text-[15px] leading-[1.65] text-hero-sub">{p.copy}</p>
              </div>
            </VolumetricCard>
          </ScrollReveal>
        ))}
      </ScrollRevealParent>

      <ScrollRevealParent
        as="div"
        className="mt-8 grid grid-cols-1 gap-5 sm:grid-cols-2"
      >
        {OPERATING.map((o, i) => (
          <ScrollReveal key={o.title} axis="up" as="div" index={i}>
            <VolumetricCard
              className="h-full rounded-2xl"
              frontClassName="h-full rounded-2xl liquid-glass"
            >
              <div className="h-full p-6">
                <h3 className="text-[18px] font-medium text-foreground">{o.title}</h3>
                <p className="mt-2 text-[15px] leading-[1.65] text-hero-sub">{o.copy}</p>
              </div>
            </VolumetricCard>
          </ScrollReveal>
        ))}
      </ScrollRevealParent>
    </Section>
  )
}
