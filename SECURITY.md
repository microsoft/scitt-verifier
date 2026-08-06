# Security

Microsoft takes the security of our software products and services seriously,
which includes all source code repositories managed through our GitHub
organizations.

## Reporting security issues

**Please do not report security vulnerabilities through public GitHub issues.**

Report them to the Microsoft Security Response Center (MSRC) at
[https://msrc.microsoft.com/create-report](https://aka.ms/opensource/security/create-report),
or by email to [secure@microsoft.com](mailto:secure@microsoft.com). Encrypt your
message with our PGP key from the
[MSRC PGP key page](https://aka.ms/opensource/security/pgpkey).

You should receive a response within 24 hours. See
[microsoft.com/msrc](https://aka.ms/opensource/security/msrc) for more.

## What counts as a vulnerability here

This is a verification tool, so the severe class of bug is one where it says
**yes** when the honest answer is **no**:

* A tampered statement or artifact that exits 0
* A receipt that verifies against a statement it does not commit to
* A receipt from one transparency service satisfying a policy scoped to another
* A policy assertion reported as `pass` without actually being evaluated
* Any input that causes a panic or unbounded resource use — a gate that crashes
  is a gate that gets bypassed

Also in scope, though lower severity: a limitation that is **not** reported in
the `notChecked` field of the evidence record. Silent gaps in coverage are the
thing this design is most concerned with.

## Out of scope

* Documented limitations listed in [docs/limitations.md](docs/limitations.md)
  and reported at runtime
* Exit 3 outcomes caused by stale trust material — this is the intended
  behaviour
* Weaknesses in a relying party's own policy document

## Policy

Microsoft follows
[Coordinated Vulnerability Disclosure](https://aka.ms/opensource/security/cvd).
