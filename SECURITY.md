# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub:
**Security > Report a vulnerability** on this repository (private vulnerability reporting).
If that option is not visible to you, open an issue that says only "security contact request", with no details, and a private channel will be arranged.

Please include the affected version or commit, a minimal input that reproduces the problem, and the impact you expect.

## What to expect

This is a personal open source project maintained on a best-effort basis. Reports are acknowledged within 7 days and I aim to ship a fix or a documented mitigation within 30 days, faster for anything that is exploitable remotely.

## Scope

In scope: bugs in this repository's code that let crafted input cause code execution, path traversal, denial of service, or wrong security findings that would mislead a reviewer.
Out of scope: findings produced about your own systems, results that depend on the sample data in `examples/`, and vulnerabilities in third-party tools this project only mentions.

## Supported versions

Only the latest release and the `main` branch receive fixes.

## Safe harbor

Good-faith research that follows this policy and avoids harming other people's data or systems is welcome and will not be pursued.
