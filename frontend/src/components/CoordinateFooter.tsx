export function CoordinateFooter() {
  return (
    <footer id="footer" className="relative border-t border-foreground/10 bg-background-soft/80 backdrop-blur-none md:backdrop-blur-[2px]">
      <div className="mx-auto max-w-[1200px] px-6 py-14">
        <div className="flex flex-col items-start justify-between gap-10 sm:flex-row sm:items-end">
          <div className="max-w-sm">
            <a
              href="#top"
              className="text-[17px] font-medium tracking-tight text-foreground"
              style={{ fontFamily: 'var(--font-general)' }}
            >
              angeronalabs
            </a>
            <p className="mt-4 text-[14px] leading-[1.6] text-foreground/50">
              Security research company building autonomous agents for
              reverse engineering and binary assurance.
            </p>
          </div>

          <div className="flex flex-col gap-3 text-right sm:items-end">
            <a
              href="mailto:shah@angeronalabs.tech"
              className="footer-link text-[15px] text-hero-sub transition-colors hover:text-foreground"
            >
              shah@angeronalabs.tech
            </a>
            <a
              href="https://www.linkedin.com/company/angeronalabs"
              target="_blank"
              rel="noreferrer"
              className="footer-link text-[15px] text-hero-sub transition-colors hover:text-foreground"
            >
              LinkedIn
            </a>
            <span className="text-[13px] text-foreground/40">
              © {new Date().getFullYear()} Angeronalabs
            </span>
          </div>
        </div>

        <div className="mt-10 flex flex-wrap gap-6 text-[13px] text-foreground/50">
          <a href="#problem" className="footer-link transition-colors hover:text-foreground">Problem</a>
          <a href="#approach" className="footer-link transition-colors hover:text-foreground">How we work</a>
          <a href="#engine" className="footer-link transition-colors hover:text-foreground">Technology</a>
          <a href="#use-cases" className="footer-link transition-colors hover:text-foreground">Who we work with</a>
          <a href="#security" className="footer-link transition-colors hover:text-foreground">Security</a>
          <a href="#faq" className="footer-link transition-colors hover:text-foreground">FAQ</a>
          <a href="#demo" className="footer-link transition-colors hover:text-foreground">Contact</a>
          <a
            href="https://www.linkedin.com/company/angeronalabs"
            target="_blank"
            rel="noreferrer"
            className="footer-link transition-colors hover:text-foreground"
          >
            LinkedIn
          </a>
        </div>
      </div>
    </footer>
  )
}
