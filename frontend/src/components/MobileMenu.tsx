import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { Button } from './ui/Button'
import { useReducedMotion } from '../lib/useReducedMotion'

const LINKS = [
  { href: '#problem', label: 'Problem' },
  { href: '#approach', label: 'How we work' },
  { href: '#engine', label: 'Technology' },
  { href: '#security', label: 'Security' },
  { href: '#faq', label: 'FAQ' },
]

export function MobileMenu() {
  const reduce = useReducedMotion()
  const [open, setOpen] = useState(false)
  const firstLinkRef = useRef<HTMLAnchorElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (open && firstLinkRef.current) {
      firstLinkRef.current.focus()
    } else if (!open && triggerRef.current) {
      triggerRef.current.focus()
    }
  }, [open])

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open])

  return (
    <div className="md:hidden">
      <button
        ref={triggerRef}
        onClick={() => setOpen((o) => !o)}
        className="flex h-10 w-10 items-center justify-center rounded-md text-foreground/90 transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-signal-violet/50"
        aria-expanded={open}
        aria-controls="mobile-menu"
        aria-label={open ? 'Close navigation menu' : 'Open navigation menu'}
      >
        <HamburgerIcon open={open} />
      </button>

      {open && createPortal(
        <>
          <div
            className={`fixed inset-0 z-[60] bg-black/50 backdrop-blur-sm ${reduce ? '' : 'animate-backdrop-in'}`}
            onClick={() => setOpen(false)}
            aria-hidden
          />
          <div
            id="mobile-menu"
            className={`fixed right-0 top-0 z-[70] h-dvh w-[min(320px,85vw)] overflow-y-auto border-l border-foreground/10 bg-background-soft/95 p-6 pt-20 shadow-2xl backdrop-blur-lg ${reduce ? '' : 'animate-panel-in'}`}
          >
            <button
              onClick={() => setOpen(false)}
              className="absolute right-4 top-4 flex h-10 w-10 items-center justify-center rounded-md text-foreground/70 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-signal-violet/50"
              aria-label="Close navigation menu"
            >
              <CloseIcon />
            </button>
            <nav className="flex flex-col gap-4" aria-label="Mobile">
              {LINKS.map((link, i) => (
                <a
                  key={link.href}
                  ref={i === 0 ? firstLinkRef : undefined}
                  href={link.href}
                  onClick={() => setOpen(false)}
                  className="text-[18px] text-foreground/90 transition-colors hover:text-foreground"
                >
                  {link.label}
                </a>
              ))}
              <Button
                variant="primary"
                size="md"
                href="mailto:shah@angeronalabs.tech?subject=Private%20alpha%20request"
                className="mt-4 w-full"
              >
                Request access
              </Button>
            </nav>
          </div>
        </>, document.body
      )}
    </div>
  )
}

function HamburgerIcon({ open }: { open: boolean }) {
  return (
    <svg
      width="20"
      height="20"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      focusable="false"
      className="transition-transform duration-200"
      style={{ transform: open ? 'rotate(90deg)' : 'rotate(0deg)' }}
    >
      <line x1="3" y1="6" x2="21" y2="6" />
      <line x1="3" y1="12" x2="21" y2="12" />
      <line x1="3" y1="18" x2="21" y2="18" />
    </svg>
  )
}

function CloseIcon() {
  return (
    <svg
      width="20"
      height="20"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      focusable="false"
    >
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  )
}
