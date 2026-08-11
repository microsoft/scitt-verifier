# Support

## Getting help

* **Questions and bugs** — open a
  [GitHub issue](https://github.com/microsoft/scitt-verifier/issues).
* **Security vulnerabilities** — see [SECURITY.md](SECURITY.md). Do not open a
  public issue.

## Before filing a bug

Include the output of `scitt-verifier --version`, the exact command line, and
the verification record (`--result`). The verification record contains the digests and
assertion outcomes needed to reproduce a decision, and is usually enough on its
own.

If the tool reported a verdict you disagree with, `scitt-verifier inspect` on
the same statement is the fastest way to see what it actually parsed.

## Support policy

This project is provided as-is. Support is best effort through GitHub issues.
See [docs/distribution.md](docs/distribution.md#positioning) for the open
question about whether this becomes a supported product.
