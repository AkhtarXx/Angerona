import { useState } from 'react'
import { Section } from '../ui/Section'
import { Button } from '../ui/Button'
import { ScrollReveal } from '../ScrollReveal'
import { SectionHeading } from '../SectionHeading'
import { SectionGlow } from '../SectionGlow'

export default function CTA() {
  const [email, setEmail] = useState('')
  const [status, setStatus] = useState<'idle' | 'draft' | 'copied' | 'error'>('idle')

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const value = email.trim()
    if (!value || !value.includes('@')) {
      setStatus('error')
      return
    }
    window.location.href = `mailto:shah@angeronalabs.tech?subject=Engagement%20inquiry&body=Contact: ${encodeURIComponent(value)}`
    setStatus('draft')
  }

  const copyEmail = async () => {
    try {
      await navigator.clipboard.writeText('shah@angeronalabs.tech')
      setStatus('copied')
    } catch {
      setStatus('error')
    }
  }

  return (
    <Section id="demo" className="py-20 sm:py-28">
      <SectionGlow x="center" y="center" color="violet" size="lg" />
      <ScrollReveal axis="scale">
        <div className="cta-panel relative rounded-2xl border border-foreground/10 bg-foreground/[0.03] px-6 py-16 backdrop-blur-none md:backdrop-blur-[2px] sm:px-10 sm:py-20">
          <SectionHeading className="max-w-[780px]">
            Start an engagement.
          </SectionHeading>

          <p className="mt-6 max-w-[540px] text-[16px] leading-[1.65] text-hero-sub">
            Tell us what you are building and we will get back within one
            business day.
          </p>

          <form
            onSubmit={handleSubmit}
            className="mt-10 flex max-w-md flex-col gap-3 sm:flex-row"
            aria-label="Start an engagement"
          >
            <input
              type="email"
              value={email}
              onChange={(e) => {
                setEmail(e.target.value)
                if (status !== 'idle') setStatus('idle')
              }}
              placeholder="you@company.com"
              required
              className="flex-1 rounded-full border border-foreground/15 bg-background-soft/60 px-5 py-3 text-[15px] text-foreground outline-none transition-colors placeholder:text-foreground/35 focus:border-signal-violet/50 focus-visible:ring-2 focus-visible:ring-signal-violet/40"
            />
            <Button
              variant="primary"
              size="lg"
              type="submit"
              className="shrink-0 justify-center"
            >
              Open email draft
            </Button>
          </form>

          <div
            className="mt-3 min-h-[24px]"
            aria-live="polite"
            aria-atomic="true"
          >
            {(status === 'draft' || status === 'copied') && (
              <p className="text-[14px] text-signal-cyan">
                {status === 'copied' ? 'Email address copied.' : 'Send the draft in your email app to contact us. No request has been submitted by this page.'}
                {' '}
                <button
                  type="button"
                  onClick={copyEmail}
                  className="underline underline-offset-2 hover:text-signal-cyan-dim focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-signal-violet/50 rounded-sm"
                >
                  Copy our email
                </button>
                .
              </p>
            )}
            {status === 'error' && (
              <p className="text-[14px] text-signal-amber">
                Please enter a valid email address, or{' '}
                <button
                  type="button"
                  onClick={copyEmail}
                  className="underline underline-offset-2 hover:text-signal-amber-dim focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-signal-violet/50 rounded-sm"
                >
                  copy our email
                </button>
                .
              </p>
            )}
          </div>
        </div>
      </ScrollReveal>
    </Section>
  )
}
