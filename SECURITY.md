# Security Audit Status

The weekly `security-audit.yml` workflow (Trivy + Grype, `--fail-on high --only-fixed`)
scans the published `:latest` image every Tuesday. This file tracks known,
investigated exceptions so the CI state doesn't need to be re-diagnosed from scratch
each time it comes up.

## Old vulnerable image tags left publicly pullable (found 2026-07-21, fixed)

Same root cause as `nginx-hardened`: `build-push.yml` pushes a new immutable version
tag (e.g. `9.20.24`) on every run, in addition to `:latest`, on both Docker Hub and
GHCR, and never retired the previous one. Only one semver tag (`9.20.24`) existed at
the time this was fixed, so there was no existing backlog to clean up here -- fixed
proactively before it could accumulate, unlike the other `docker-hardened` repos.

Fixed by `registry-cleanup.yml` (`scripts/prune-registry-tags.sh` for Docker Hub,
`scripts/prune-ghcr-tags.sh` for GHCR), called as a job from `build-push.yml` after
every push, and directly `workflow_dispatch`-able. Keeps the last 3 semver tags +
`:latest`. Only ever deletes a package version by its own named tag -- untagged
manifest-list children, attestations, and cosign signatures are left alone.

**Important caveat** (hit on `nginx-hardened`'s first run): "keep the last 3 semver
tags" is generic hygiene, not CVE-aware. After any prune run, cross-check the
surviving semver tags with a direct `grype <image>:<tag> --fail-on high --only-fixed`
scan -- if one inside the keep-window is still flagged, delete it explicitly.
