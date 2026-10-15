import { useState } from 'react'
import { Section } from '../ui/Section'
import { SectionHeading } from '../SectionHeading'
import { ScrollReveal, ScrollRevealParent } from '../ScrollReveal'
import { cn } from '../../lib/cn'

const FAQS = [
  {
    q: 'Do you need our source code?',
    a: 'No. We work from the compiled binary alone. In fact most engagements start precisely because the source is unavailable, outdated, or cannot be shared.',
  },
  {
    q: 'Where does the analysis run?',
    a: 'Engines and run workspaces are local. Subscription-agent workflows can send prompts and binary-derived context to their configured provider; an air-gapped workflow requires local models plus the no-network privacy and sandbox settings.',
  },
  {
    q: 'What binary formats and architectures do you support?',
    a: 'Current tests emphasize ELF, x86-64, C++ recovery, and Solana BPF. IDA and Ghidra can expose additional formats and architectures, while Angerona also has custom-ISA processors. Quality varies by target, and Mach-O triage is currently limited.',
  },
  {
    q: 'How do you verify a finding is real and not a hallucination?',
    a: 'Angerona records results from the verification gates available for that run, including claim, capability, structural, semantic, and behavioral checks. Missing tooling remains unavailable or unverified instead of becoming positive evidence; a security reviewer still makes the final judgment.',
  },
  {
    q: 'What does a report contain?',
    a: 'Reports can include recovered symbols, addresses, entry-to-sink paths, confidence, supporting artifacts, and verification status. Evidence depth depends on the target and the tools available during the run.',
  },
  {
    q: 'How is pricing structured?',
    a: 'Private alpha cohorts are onboarding now. Reach out and we will scope pricing to your target set and deployment model rather than a one-size quote.',
  },
]

export default function FAQ() {
  const [open, setOpen] = useState<number | null>(0)

  return (
    <Section id="faq">
      <ScrollReveal>
        <SectionHeading className="mb-16">Questions before you reach out</SectionHeading>
      </ScrollReveal>

      <ScrollRevealParent as="div" className="flex flex-col">
        {FAQS.map((item, i) => {
          const isOpen = open === i
          return (
            <ScrollReveal key={item.q} axis="fade" as="div" index={i}>
              <div
                className={cn(
                  'border-t border-foreground/10 transition-colors duration-300 last:border-b',
                  isOpen && 'bg-foreground/[0.02]',
                )}
              >
                <button
                  onClick={() => setOpen(isOpen ? null : i)}
                  className="flex w-full items-center justify-between gap-6 py-6 px-2 text-left"
                  aria-expanded={isOpen}
                >
                  <span
                    className={cn(
                      'text-[18px] font-medium transition-colors duration-300 sm:text-[20px]',
                      isOpen ? 'text-foreground' : 'text-foreground/90',
                    )}
                  >
                    {item.q}
                  </span>
                  <span
                    className={cn(
                      'shrink-0 font-mono text-[18px] text-foreground/60 transition-transform duration-300',
                      isOpen && 'rotate-45',
                    )}
                    aria-hidden
                  >
                    +
                  </span>
                </button>
                <div
                  className={cn(
                    'grid transition-[grid-template-rows] duration-[400ms] ease-[cubic-bezier(0.22,1,0.36,1)] motion-reduce:transition-none',
                    isOpen ? 'grid-rows-[1fr] pb-6' : 'grid-rows-[0fr]',
                  )}
                >
                  <p className="overflow-hidden max-w-[760px] px-2 text-[15px] leading-[1.65] text-hero-sub">
                    {item.a}
                  </p>
                </div>
              </div>
            </ScrollReveal>
          )
        })}
      </ScrollRevealParent>
    </Section>
  )
}
