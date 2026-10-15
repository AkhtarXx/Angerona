import { Section } from '../ui/Section'
import { SectionHeading } from '../SectionHeading'
import { ScrollReveal, ScrollRevealParent } from '../ScrollReveal'
import { VolumetricCard } from '../VolumetricCard'
import { SectionGlow } from '../SectionGlow'
import { PipelineDiagram } from '../PipelineDiagram'
import { SearchIcon, WorkflowIcon, ShieldIcon, ReportIcon } from '../icons'

const STEP_ICONS = [SearchIcon, WorkflowIcon, ShieldIcon, ReportIcon]

const STEPS = [
  {
    title: 'Ingest',
    copy: 'An authorized target is analyzed with a configured reverse-engineering engine and stored in a local review workspace.',
  },
  {
    title: 'Recover',
    copy: 'Deterministic passes organize binary-derived evidence into a consistent model for further investigation.',
  },
  {
    title: 'Investigate',
    copy: 'Optional bounded agents help analysts prioritize candidate risks and keep each claim tied to supporting artifacts.',
  },
  {
    title: 'Verify',
    copy: 'Available evidence checks record whether a claim is supported, contradicted, unavailable, or still requires review.',
  },
]

export default function HowItWorks() {
  return (
    <Section id="approach">
      <SectionGlow x="center" y="center" color="violet" size="md" parallaxRate={0.04} />
      <ScrollReveal>
        <SectionHeading className="mb-4">How we work</SectionHeading>
      </ScrollReveal>
      <ScrollReveal delay={0.08} as="p" axis="words" className="mb-10 max-w-[640px] text-[17px] leading-[1.65] text-hero-sub">
        Binary in, reviewable evidence out. Static extraction and deterministic
        passes create local artifacts; optional agents investigate and review them.
      </ScrollReveal>

      <ScrollReveal axis="fade">
        <PipelineDiagram className="mb-16" />
      </ScrollReveal>

      <ScrollRevealParent
        as="div"
        className="relative grid grid-cols-1 gap-6 md:grid-cols-2 md:gap-x-8 md:gap-y-8"
      >
        <div
          className="pointer-events-none absolute top-0 bottom-0 left-1/2 hidden w-px -translate-x-1/2 bg-gradient-to-b from-transparent via-foreground/10 to-transparent md:block"
          aria-hidden
        />
        {STEPS.map((s, i) => {
          const Icon = STEP_ICONS[i] ?? SearchIcon
          return (
            <ScrollReveal key={s.title} axis="up" as="div" index={i}>
              <VolumetricCard
                className="h-full rounded-2xl"
                frontClassName="h-full rounded-2xl liquid-glass"
              >
                <div className="relative h-full p-6 sm:p-7">
                  <span
                    className="pointer-events-none absolute right-6 top-4 font-mono text-[clamp(64px,10vw,120px)] leading-none text-foreground/[0.04] select-none"
                    aria-hidden
                  >
                    0{i + 1}
                  </span>
                  <div className="relative flex items-baseline gap-3">
                    <Icon className="text-signal-violet" size={18} />
                    <span className="font-mono text-[13px] text-steel">
                      0{i + 1}
                    </span>
                    <h3 className="text-[20px] font-medium text-foreground sm:text-[22px]">
                      {s.title}
                    </h3>
                  </div>
                  <p className="relative mt-3 text-[15px] leading-[1.65] text-hero-sub">{s.copy}</p>
                </div>
              </VolumetricCard>
            </ScrollReveal>
          )
        })}
      </ScrollRevealParent>
    </Section>
  )
}
