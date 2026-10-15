import { Section } from '../ui/Section'
import { SectionHeading } from '../SectionHeading'
import { ScrollReveal, ScrollRevealParent } from '../ScrollReveal'
import { VolumetricCard } from '../VolumetricCard'
import { SectionGlow } from '../SectionGlow'

const PROBLEMS = [
  {
    title: 'Binaries arrive without source',
    copy: 'Firmware, vendor drivers, and legacy binaries land on your desk stripped. Symbols, types, and structure are gone before you ever start.',
  },
  {
    title: 'Manual analysis does not scale',
    copy: 'A single sample can take days of patient work in IDA or Ghidra. By the time the analysis is done, the exploit is already in the wild.',
  },
  {
    title: 'Findings without evidence do not hold',
    copy: 'A hypothesis from decompilation is cheap. Converting it into a verified, reproducible result is where most reverse engineering effort disappears.',
  },
]

export default function Problem() {
  return (
    <Section id="problem">
      <SectionGlow x="left" y="center" color="violet" size="lg" parallaxRate={0.05} />
      <ScrollReveal>
        <SectionHeading className="mb-4">
          Manual reverse engineering does not scale
        </SectionHeading>
      </ScrollReveal>

      <ScrollReveal delay={0.08} as="p" axis="words" className="mb-16 max-w-[640px] text-[17px] leading-[1.65] text-hero-sub">
        Security teams are expected to defend compiled code with the same manual
        workflow the field has used for twenty years. The gap between what gets
        shipped and what gets analyzed keeps widening.
      </ScrollReveal>

      <ScrollRevealParent
        as="div"
        className="grid grid-cols-1 gap-6 md:grid-cols-3 md:gap-8"
      >
        {PROBLEMS.map((p, i) => (
          <ScrollReveal key={p.title} axis="up" as="div" index={i}>
            <VolumetricCard
              className="h-full rounded-2xl"
              frontClassName="h-full rounded-2xl liquid-glass"
            >
              <div className="h-full p-6">
                <h3 className="text-[20px] font-medium text-foreground">{p.title}</h3>
                <p className="mt-3 text-[15px] leading-[1.65] text-hero-sub">{p.copy}</p>
              </div>
            </VolumetricCard>
          </ScrollReveal>
        ))}
      </ScrollRevealParent>
    </Section>
  )
}
