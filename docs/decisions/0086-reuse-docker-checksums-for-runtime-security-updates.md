# 0086. Reuse Docker checksums for runtime security updates

- Status: Accepted; fresh exact-image qualification required
- Date: 2026-09-12
- Rung: native-platform

## Context

The retained Hermes runtime archive fails its current security scan on twelve
fixable HIGH/CRITICAL findings in four Debian packages. Both the current pinned
uv base and the latest uv/Python 3.13 slim bases still contain the affected
versions. Debian's signed APT indexes supply fixes for the same distribution.

## Decision

Use Docker's built-in `ADD --checksum` to fetch four exact official Debian
packages, then native `dpkg --install` with RUN networking disabled. Pin the
URLs and SHA-256 values in the existing attested Dockerfile. Install before
Hermes source is copied; only reviewed distribution maintainer scripts execute
in this step. Third-party Python hooks remain inside networkless gVisor.

The selected amd64 packages total 3,018,384 download bytes:

| Package | Version | Bytes |
| --- | --- | ---: |
| gzip | 1.13-1+deb13u1 | 138608 |
| libpcre2-8-0 | 10.46-1~deb13u2 | 298872 |
| libsqlite3-0 | 3.46.1-7+deb13u2 | 914584 |
| perl-base | 5.40.1-6+deb13u1 | 1666320 |

**Tradeoff:** Docker handles checksum verification and caching without a custom
fetcher or another registry. Its download happens outside RUN network isolation;
the fixed downloads remain in intermediate image layers after removal from the
final filesystem. The existing build deadline bounds the build, not each download's
byte count. Maintainers authenticate hashes through Debian's signed indexes
before changing this recipe; HTTPS alone is not the package trust decision.

**Rejected:** A base-tag refresh alone leaves the vulnerabilities present. An
unbounded `apt-get upgrade` introduces unresolved build inputs. A custom download
and package-verification framework duplicates Docker and Debian functionality.

## Consequences

The existing adapter recipe digest binds the updates; historical qualification
cannot certify them. Require a fresh complete runtime build, current scan and
native qualification before promotion. No scan exceptions or runtime authority
changes follow from this patch. This recipe remains qualified only on amd64.
Remove the overlay when a reviewed base includes these fixes and passes the
same tests; revisit if dependencies require a larger downstream package set.

References: [Docker checksum verification](https://docs.docker.com/reference/dockerfile/#add---checksum),
[gzip fix](https://security-tracker.debian.org/tracker/CVE-2026-41992),
[PCRE2 fix](https://security-tracker.debian.org/tracker/CVE-2026-86145),
[SQLite fix](https://security-tracker.debian.org/tracker/CVE-2026-11822),
[Perl fix](https://security-tracker.debian.org/tracker/CVE-2026-13221).
