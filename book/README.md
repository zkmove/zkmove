# zkMove Documentation

This directory contains the zkMove documentation site built with [mdBook](https://rust-lang.github.io/mdBook/).

## Read Online

- [User Guide](https://www.zkmove.net/document/user/setup-dev-environment/) — step-by-step tutorial for creating a zkMove circuit, generating a proof, and verifying it on-chain.
- [Litepaper](https://www.zkmove.net/document/litepaper/abstract/) — technical overview of zkMove's design and architecture.

## Local Preview

```bash
make docs-serve
```

## Build

From this directory:

```bash
make docs-build
```

Or from the repository root:

```bash
mdbook build book
```

The generated static site is written to `book/book/` and deployed to GitHub Pages by `../.github/workflows/docs-gh-pages.yml`.
