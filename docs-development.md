# Docs Development and Deployment

## Local Preview

```bash
make docs-serve
```

The local URL is usually:

- `http://127.0.0.1:8000`

## Strict Build Check

```bash
make docs-build
```

## GitHub Pages Deployment

Deployment is handled by:

- `.github/workflows/docs-gh-pages.yml`

It runs on:

- Push to `main` with docs-related changes
- Manual trigger (`workflow_dispatch`)

## Docs Structure

- English: `docs/en/**`
- Chinese: `docs/zh/**`

## Maintenance Notes

- Keep `mkdocs.yml` navigation in sync when adding or moving pages.
- Keep page titles concise for better sidebar readability.
