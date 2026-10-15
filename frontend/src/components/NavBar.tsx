import { useReducedMotion } from '../lib/useReducedMotion'
import { useScrollState } from '../lib/useScrollState'
import { Button } from './ui/Button'
import { MobileMenu } from './MobileMenu'
import { BrandLogo } from './BrandLogo'

export function NavBar() {
  const reduce = useReducedMotion()
  const { y } = useScrollState()
  const progress = Math.min(1, y / 80)

  return (
    <div
      className={`fixed left-0 right-0 top-0 z-50 w-full border-b border-transparent px-6 py-4 transition-[background-color,border-color,backdrop-filter] duration-300 sm:px-8 ${
        reduce ? '' : 'animate-nav-in'
      }`}
      style={{
        backgroundColor: `rgba(8, 4, 24, ${progress * 0.85})`,
        borderColor: `rgba(245, 243, 240, ${progress * 0.1})`,
        backdropFilter: `blur(${progress * 12}px)`,
      }}
    >
      <nav
        className="mx-auto flex w-full max-w-[1200px] items-center justify-between rounded-[var(--radius-buttons)]"
        aria-label="Primary"
      >
        <a
          href="#top"
          aria-label="AngeronaLabs home"
          className="flex items-center rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-signal-cyan/60 focus-visible:ring-offset-2 focus-visible:ring-offset-transparent"
        >
          <BrandLogo className="transition-opacity hover:opacity-90" />
        </a>

        <div className="hidden items-center gap-8 md:flex">
          {[
            { label: 'Problem', href: '#problem' },
            { label: 'How we work', href: '#approach' },
            { label: 'Technology', href: '#engine' },
            { label: 'Security', href: '#security' },
            { label: 'FAQ', href: '#faq' },
          ].map((item) => (
            <a
              key={item.href}
              href={item.href}
              className="nav-link text-[15px] text-foreground/90 transition-colors hover:text-foreground rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-signal-cyan/60 focus-visible:ring-offset-2 focus-visible:ring-offset-transparent"
            >
              {item.label}
            </a>
          ))}
        </div>

        <div className="relative z-10 flex shrink-0 items-center gap-3">
          <Button variant="heroSecondary" size="md" href="#demo" className="hidden px-4 py-2 sm:inline-flex">
            Contact us
          </Button>
          <MobileMenu />
        </div>
      </nav>
    </div>
  )
}
