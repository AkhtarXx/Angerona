# AngeronaLabs website

This directory contains the public AngeronaLabs product and company website. It
is a React, TypeScript, Tailwind CSS, and Vite application.

It is intentionally separate from Angerona's local analysis control panel:

- `frontend/` is the public informational website.
- `src/web/` is the local product UI served by `angerona web`.

Building this site must not write into `src/web/static/`.

## Requirements

- Node.js 24 (qualification used 24.19)
- npm 10 or newer

## Development

```bash
cd frontend
npm ci
npm run dev
```

Vite starts the development server at `http://127.0.0.1:5173` by default.
`ANGERONA_BACKEND` can override the optional local API proxy target.

## Quality checks

```bash
npm run check
```

The check command runs the linter, TypeScript compiler, and production build.
The build output is `frontend/dist/` and is ignored by Git.

Run the browser tests separately when Playwright browsers are installed:

```bash
npm run test:e2e
```

## Cloudflare Pages deployment

The workflow at `.github/workflows/deploy-cloudflare-pages.yml` builds and
deploys the site after every push to `main` that changes `frontend/` or the
workflow itself, once `CLOUDFLARE_PAGES_PROJECT` is configured. Without that
variable the deployment job is skipped, so a fresh clone/fork cannot deploy a
website by accident. It can also be started manually from GitHub Actions.

Configure these once under **GitHub repository settings > Secrets and variables
> Actions**:

| Type | Name | Value |
|---|---|---|
| Secret | `CLOUDFLARE_API_TOKEN` | A scoped Cloudflare token with Pages edit access. |
| Secret | `CLOUDFLARE_ACCOUNT_ID` | The Cloudflare account containing the existing Pages project. |
| Variable | `CLOUDFLARE_PAGES_PROJECT` | The exact existing Cloudflare Pages project name. |

The workflow deliberately disables automatic project creation. A misspelled
project name therefore fails instead of silently deploying a second website.
Credentials remain in GitHub Secrets and must never be committed.

For engineering review, follow the root [Git sharing policy](../docs/SHARING.md).
Track required website assets and the [font license](public/fonts/OFL.txt); keep
dependencies, build output, screenshots and internal design/presentation files
ignored.

Build the same production directory locally with:

```bash
npm ci
npm run check
```

The deployable output is:

```text
frontend/dist/
```

Generated screenshots, audit captures, browser traces, test results, PDFs, and
slide exports are intentionally ignored. Keep editable source files and asset
provenance in version control.
