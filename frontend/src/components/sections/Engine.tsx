import { lazy, Suspense } from 'react'
import { Section } from '../ui/Section'
import { SectionHeading } from '../SectionHeading'
import { Button } from '../ui/Button'
import { ScrollReveal, ScrollRevealParent } from '../ScrollReveal'
import { VolumetricCard } from '../VolumetricCard'
import { SectionGlow } from '../SectionGlow'
import { BinaryIcon, LockIcon, SearchIcon, ShieldIcon, WorkflowIcon } from '../icons'

const Terminal = lazy(() => import('../Terminal'))

const STACK = [
  { title: 'Engine-assisted analysis', copy: 'Output from configured reverse-engineering tools is organized into a shared analysis model.', icon: SearchIcon },
  { title: 'Local-first deployment', copy: 'Work runs on your machines. Binary-derived data is treated as untrusted by design.', icon: LockIcon },
  { title: 'Evidence status', copy: 'Available checks record whether a claim is supported, contradicted, unavailable, or still unverified.', icon: ShieldIcon },
  { title: 'Review trail', copy: 'Relevant plans, analysis artifacts, review notes, and reports are retained for authorized review.', icon: WorkflowIcon },
]

export default function Engine() {
  return (
    <Section id="engine">
      <SectionGlow x="right" y="top" color="indigo" size="lg" />
      <ScrollReveal>
        <SectionHeading className="mb-16">Our technology</SectionHeading>
      </ScrollReveal>

      <ScrollRevealParent
        as="div"
        className="grid grid-cols-1 gap-4 sm:grid-cols-2"
      >
        <ScrollReveal axis="up" as="div" index={0}>
          <VolumetricCard
            className="h-full rounded-2xl"
            frontClassName="h-full rounded-2xl liquid-glass"
          >
            <div className="flex h-full flex-col justify-between p-6 sm:p-8">
              <div>
                <div className="flex items-center gap-3">
                  <BinaryIcon className="text-signal-violet" />
                  <h3
                    className="font-medium text-foreground"
                    style={{ fontFamily: 'var(--font-general)', fontSize: 'clamp(26px, 3vw, 32px)', letterSpacing: '-0.02em' }}
                  >
                    Local-first analysis stack
                  </h3>
                </div>
                <p className="mt-4 max-w-sm text-[15px] leading-[1.65] text-hero-sub">
                  Decompilation, recovery, investigation, and verification in one modular stack
                  that stays inside your environment.
                </p>
              </div>
              <Suspense
                fallback={
                  <div className="mt-8 min-h-[220px] w-full rounded-[var(--radius-cards)] border border-foreground/10 bg-background-soft/50" aria-hidden />
                }
              >
                <Terminal className="mt-8 w-full" />
              </Suspense>
              <Button
                variant="heroSecondary"
                href="mailto:shah@angeronalabs.tech?subject=Private%20alpha%20request"
                className="mt-6 w-fit px-5 py-2.5"
              >
                Request a demo
              </Button>
            </div>
          </VolumetricCard>
        </ScrollReveal>

        {STACK.map((item, i) => (
          <ScrollReveal key={item.title} axis="up" as="div" index={i + 1}>
            <VolumetricCard
              className="h-full rounded-2xl"
              frontClassName="h-full rounded-2xl liquid-glass"
            >
              <div className="h-full p-6">
                <item.icon className="mb-4 text-foreground/60" />
                <h4 className="text-[17px] font-medium text-foreground">{item.title}</h4>
                <p className="mt-2 text-[15px] leading-[1.65] text-hero-sub">{item.copy}</p>
              </div>
            </VolumetricCard>
          </ScrollReveal>
        ))}
      </ScrollRevealParent>
    </Section>
  )
}
