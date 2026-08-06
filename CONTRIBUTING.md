# Contributing

## Getting started

```console
cargo build
cargo test
```

No system dependencies. The default crypto backend is pure Rust, so there is no
OpenSSL, no C compiler, and no platform linker to install.

## The rules that are not negotiable

These are enforced in CI. If a change needs to break one, that is a design
discussion, not a pull request.

**`scitt-receipt` performs no I/O, reads no clock, and returns no verdicts.**
The core has to be embeddable in a browser. `std::fs`, `SystemTime`, `ExitCode`,
and any network client are rejected by the `boundary` job.

**A check that did not run is never reported as a pass.** Results are
`Option<bool>`. `None` means "did not run" and must never be collapsed into
success. If you add a check, make sure `fully_verified()` requires it explicitly.

**Unimplemented options are refused, not ignored.** If a flag or a policy
assertion is not implemented, the tool exits 4 with an explanation. Accepting
and silently skipping it reports success for a check nobody performed.

**New limitations are added to `notChecked`.** If your change means something is
no longer verified, say so at runtime, not only in the documentation. There is a
test asserting that `notChecked` is non-empty even on a passing run.

**Exit codes are the public contract.** Pipelines branch on them. Changing what
a code means is a breaking change.

## Tests

* `crates/scitt-receipt/tests/conformance.rs` — the core against real MST
  fixtures, with digests pinned to values cross-checked against the .NET
  prototype and `pyscitt`. **Do not update a pinned constant to match new
  output.** If a digest changes, the meaning of "the same statement" changed,
  and that needs explaining before it needs fixing.
* `crates/scitt-verifier/tests/acceptance.rs` — the CLI contract: exit codes,
  refusals, and evidence fields.

Every bug fix needs a test that fails without it. For this kind of tool, a
regression is not an inconvenience — it is a false negative in a security gate.

## Adding a policy assertion

1. Add the field to `Assertions` in `crates/scitt-policy/src/lib.rs`.
2. Add a branch in `evaluate` that returns `CannotEvaluate` when the input is
   absent. Never `Pass`.
3. Update `is_empty`, or a policy containing only your new assertion will be
   rejected as empty.
4. Document it in `docs/policy.md`.
5. Add a test for all three outcomes, including `cannotEvaluate`.

Note that `deny_unknown_fields` means older binaries reject policies using your
new assertion. That is intended, and worth mentioning in release notes.

## Style

Comments explain *why*, not *what*. `cargo fmt` and `cargo clippy` are enforced;
run them before pushing.

## Contributor Licence Agreement

Most contributions require you to agree to a Contributor Licence Agreement
declaring that you have the right to, and actually do, grant us the rights to
use your contribution. Visit <https://cla.opensource.microsoft.com>.

When you submit a pull request, a CLA bot will determine whether you need to
provide a CLA and decorate the PR appropriately. You only need to do this once
across all repositories using our CLA.

This project has adopted the
[Microsoft Open Source Code of Conduct](CODE_OF_CONDUCT.md).

## Trademarks

This project may contain trademarks or logos for projects, products, or
services. Authorised use of Microsoft trademarks or logos is subject to and must
follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/legal/intellectualproperty/trademarks/usage/general).
Use of third-party trademarks or logos is subject to those third parties'
policies.
