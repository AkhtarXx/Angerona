import { Section } from '../ui/Section'
import { SectionHeading } from '../SectionHeading'
import { ScrollReveal, ScrollRevealParent } from '../ScrollReveal'
import { VolumetricCard } from '../VolumetricCard'
import { SectionGlow } from '../SectionGlow'
import { AnimatedMeter } from '../AnimatedMeter'

const FINDINGS = [
  {
    symbol: 'example_function_a',
    verdict: 'Candidate memory-safety issue',
    confidence: 0.94,
    evidence:
      'Illustrative evidence connects an untrusted length to a sensitive operation and preserves the path for analyst review.',
    gates: ['static evidence', 'path review'],
  },
  {
    symbol: 'example_function_b',
    verdict: 'Candidate arithmetic issue',
    confidence: 0.81,
    evidence:
      'Illustrative recovered logic highlights an arithmetic edge case and records the assumptions behind the claim.',
    gates: ['semantic review'],
  },
  {
    symbol: 'example_function_c',
    verdict: 'No supported path identified',
    confidence: 0.88,
    evidence:
      'Illustrative checks did not support the initial hypothesis; the report keeps that result visible instead of upgrading it to a finding.',
    gates: ['behavioral check', 'analyst review'],
  },
]

export default function SampleReport() {
  return (
    <Section id="report">
      <SectionGlow x="left" y="bottom" color="indigo" size="md" />
      <ScrollReveal>
        <SectionHeading className="mb-4">A report, not a best guess.</SectionHeading>
      </ScrollReveal>
      <ScrollReveal delay={0.08}>
        <p className="mb-16 max-w-[640px] text-[17px] leading-[1.65] text-hero-sub">
          This synthetic preview shows the shape of a review record: a recovered
          location, supporting evidence, confidence, and the status of available
          checks. It is not an analysis result from a customer or bundled sample.
        </p>
      </ScrollReveal>

      <ScrollRevealParent as="div" className="flex flex-col gap-5">
        {FINDINGS.map((f, i) => (
          <ScrollReveal key={f.symbol} axis="left" as="div" index={i}>
            <VolumetricCard
              className="rounded-2xl"
              frontClassName="rounded-2xl liquid-glass"
            >
              <FindingFace finding={f} />
            </VolumetricCard>
          </ScrollReveal>
        ))}
      </ScrollRevealParent>
    </Section>
  )
}

function FindingFace({ finding }: { finding: (typeof FINDINGS)[number] }) {
  return (
    <div className="relative p-6 sm:p-7">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-baseline gap-3 font-mono text-[14px]">
          <span className="text-foreground">{finding.symbol}</span>
          <span className="text-steel">·</span>
          <span className="text-foreground/90">{finding.verdict}</span>
        </div>
        <ConfidenceMeter value={finding.confidence} />
      </div>

      <p className="mt-4 max-w-[760px] text-[15px] leading-[1.65] text-hero-sub">
        {finding.evidence}
      </p>

      <div className="mt-5 flex flex-wrap items-center gap-2">
        <span className="text-[12px] text-steel">evidence from</span>
        {finding.gates.map((g) => (
          <span
            key={g}
            className="rounded-md border border-foreground/15 bg-foreground/[0.04] px-2 py-1 font-mono text-[11px] text-foreground/80"
          >
            {g}
          </span>
        ))}
      </div>
    </div>
  )
}

function ConfidenceMeter({ value }: { value: number }) {
  const pct = Math.round(value * 100)
  return (
    <div className="flex items-center gap-2">
      <AnimatedMeter value={value} className="flex" />
      <span className="font-mono text-[12px] text-foreground/70">{pct}%</span>
    </div>
  )
}
