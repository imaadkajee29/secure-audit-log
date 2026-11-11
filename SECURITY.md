# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Use GitHub's
[private vulnerability reporting](../../security/advisories/new) instead. I aim to acknowledge
reports within 72 hours.

## Supported versions

Only the latest release receives security fixes.

## Verifying release images

Every release image is signed with [Sigstore cosign](https://docs.sigstore.dev/) using GitHub
OIDC (keyless), and carries SLSA provenance and SBOM attestations.

```bash
cosign verify ghcr.io/imaadkajee29/secure-audit-log@<digest> \
  --certificate-identity-regexp 'https://github.com/imaadkajee29/secure-audit-log/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Automated controls

| Control                   | Tool                          | When                  |
| ------------------------- | ----------------------------- | --------------------- |
| Static analysis (SAST)    | CodeQL `security-extended`    | Every push/PR, weekly |
| Secret scanning           | Gitleaks (full history)       | Every push/PR         |
| Dependency audit (SCA)    | `npm audit`, signature check  | Every push/PR, weekly |
| PR dependency review      | GitHub dependency-review      | Every PR              |
| Container vulnerabilities | Trivy (gate on HIGH/CRITICAL) | Every push, release   |
| Dockerfile / config lint  | Hadolint, Trivy misconfig     | Every push            |
| SBOM                      | Syft (SPDX)                   | Every build, release  |
| Dependency updates        | Dependabot                    | Weekly                |
