import { Section } from '../ui/Section'
import { SectionHeading } from '../SectionHeading'
import { ScrollReveal, ScrollRevealParent } from '../ScrollReveal'
import { VolumetricCard } from '../VolumetricCard'
import { SectionGlow } from '../SectionGlow'

const FOUNDERS = [
  {
    name: 'Akhtar Shah',
    role: 'Founder, Engineering',
    bio: 'Builds the agents, the engine, and the verification gates. Reverse engineering, distributed systems, and binary analysis tooling.',
  },
  {
    name: 'You?',
    role: 'Security research lead',
    bio: 'We are looking for a hands-on reverse engineer to shape the first private alpha engagements and define the research roadmap.',
  },
]

export default function Team() {
  return (
    <Section id="team">
      <SectionGlow x="left" y="bottom" color="faint" size="md" />
      <ScrollReveal>
        <SectionHeading className="mb-4">Who is building this</SectionHeading>
      </ScrollReveal>
      <ScrollReveal delay={0.08}>
        <p className="mb-16 max-w-[640px] text-[17px] leading-[1.65] text-hero-sub">
          Angeronalabs is a focused research company. We are building the engine
          and running the first engagements ourselves, not outsourcing the hard parts.
        </p>
      </ScrollReveal>

      <ScrollRevealParent
        as="div"
        className="grid grid-cols-1 gap-6 md:grid-cols-2 md:gap-8"
      >
        {FOUNDERS.map((f, i) => (
          <ScrollReveal key={f.name} axis={i === 0 ? 'left' : 'right'} as="div" index={i}>
            <VolumetricCard
              className="h-full rounded-2xl"
              frontClassName="h-full rounded-2xl liquid-glass"
            >
              <div className="flex h-full flex-col p-6 sm:p-8">
                <div className="flex items-center gap-4">
                  <div
                    className="liquid-glass flex h-14 w-14 items-center justify-center rounded-xl"
                    aria-hidden
                  >
                    <span className="text-[18px] font-semibold text-foreground">
                      {f.name === 'You?' ? '+' : initials(f.name)}
                    </span>
                  </div>
                  <div>
                    <h3 className="text-[19px] font-medium text-foreground">{f.name}</h3>
                    <p className="text-[14px] text-foreground/60">{f.role}</p>
                  </div>
                </div>
                <p className="mt-5 text-[15px] leading-[1.65] text-hero-sub">{f.bio}</p>
              </div>
            </VolumetricCard>
          </ScrollReveal>
        ))}
      </ScrollRevealParent>
    </Section>
  )
}

function initials(name: string) {
  return name
    .split(' ')
    .map((p) => p[0])
    .slice(0, 2)
    .join('')
    .toUpperCase()
}
