# Licensing threat model

This page reviews how someone could try to get around the licensing, branding, and integrity
checks of Aevrin MCP Scanner, and what stops them. How the system works is in
[licensing.md](licensing.md).

## The starting point

The source code is public. **Anyone with the source can change it and build a copy without any
check. No client-side mechanism can prevent that.** The defenses therefore aim to:

1. make misuse **illegal** (the license and the commercial agreement),
2. make **forgery impossible** without Aevrin's private keys (Ed25519 signatures),
3. make misuse **visible** (every report states the license and build status), and
4. make bypassing it **more work** than buying a license, for an honest organization.

The attacker we design against is a company that wants commercial use without paying. The
defenses do not try to stop a skilled individual who rewrites the code for themselves: that is
covered by the license, not by technology.

Severity below means: how much harm a working attack does to Aevrin's licensing, assuming the
attacker is a company.

## Attacks

### 1. Remove the branding

| | |
|---|---|
| Attack path | Edit `branding.py` or the reporters so reports no longer name Aevrin or the license |
| Works? | Yes, on a copy whose source they change |
| Current protection | The license forbids removing notices (Required Notice lines, commercial agreement). Reports get the branding block in two independent places (engine and every reporter). In an official build, changing any file makes every report say "Modified build". CI fails if a hook is removed (`check_licensing.py`) |
| Remaining weakness | Someone who also edits the integrity check can hide the "Modified build" line |
| Mitigation | Legal enforcement. For high-value customers: ship compiled builds (see "Further hardening") |
| Severity | Medium |
| Legal, ethical, practical? | Yes. Visible notices only, nothing hidden |

### 2. Remove the license validation

| | |
|---|---|
| Attack path | Delete or short-circuit the call to `licensing.status` |
| Works? | Nothing is gained: without a license the scanner already runs fully (noncommercial terms) |
| Current protection | Removing the check only removes the notice, which is attack 1. CI and the integrity manifest detect it |
| Remaining weakness | Same as attack 1 |
| Mitigation | Same as attack 1 |
| Severity | Low (the policy does not block anything, so there is nothing to unlock) |
| Legal, ethical, practical? | Yes |

### 3. Change the license status

| | |
|---|---|
| Attack path | Make `check_license()` return "valid", or edit the saved license or receipt files |
| Works? | Editing files: no. Editing code: yes, on a changed copy |
| Current protection | Saved keys and receipts are re-verified on every run; an edited file fails its signature and is ignored. Changing code is detected by the integrity manifest in official builds |
| Remaining weakness | A changed copy can claim anything about itself. A report from it can be faked |
| Mitigation | Treat a report as proof of nothing about licensing. For audits, Aevrin checks its server records (online licenses) and the agreement |
| Severity | Medium |
| Legal, ethical, practical? | Yes |

### 4. Forge a license key

| | |
|---|---|
| Attack path | Write a license payload and sign it |
| Works? | **No.** It needs Aevrin's Ed25519 license private key |
| Current protection | Ed25519 (128-bit security level). Signatures are checked before any field is read. Keys are trusted per purpose |
| Remaining weakness | A leak of the license private key |
| Mitigation | Keep the license key offline (hardware key or password manager), encrypted with a passphrase. Rotate and revoke as in licensing.md |
| Severity | Critical if the key leaks, otherwise none |
| Legal, ethical, practical? | Yes |

### 5. Change a license key (for example the expiry or the licensee)

| | |
|---|---|
| Attack path | Decode the payload, change a field, put it back |
| Works? | **No.** Any change breaks the signature (tested in `tests/unit/test_licensing.py`) |
| Current protection | The signature covers the whole payload and the format prefix |
| Remaining weakness | None in the format |
| Mitigation | Not needed |
| Severity | None |
| Legal, ethical, practical? | Yes |

### 6. Replace the public verification key

| | |
|---|---|
| Attack path | Put their own public key into `licensing/keys.py`, then sign their own licenses |
| Works? | On a changed copy, yes |
| Current protection | There is no setting or variable that adds trusted keys. `keys.py` is covered by the release manifest (official builds show "Modified build"), pinned in CI, and owned in CODEOWNERS. A license signed by a self-made key is rejected by Aevrin's license server and by every unchanged copy |
| Remaining weakness | Same as attack 3: a changed copy can trust anything |
| Mitigation | Legal. Online licenses: Aevrin's server is the source of truth |
| Severity | Medium |
| Legal, ethical, practical? | Yes |

### 7. Remove the integrity check

| | |
|---|---|
| Attack path | Make `verify_build()` always return "official" |
| Works? | On a changed copy, yes |
| Current protection | Checking from outside the copy: compare the installed files with an official wheel verified by `gh attestation verify` and `SHA256SUMS`, or reinstall from it. Signed provenance shows what an official package looks like |
| Remaining weakness | A program cannot reliably check itself. This is the core limit of client-side checks |
| Mitigation | Verify from outside: `gh attestation verify`, `cosign verify`, and `SHA256SUMS` on the installed artifacts |
| Severity | Medium |
| Legal, ethical, practical? | Yes |

### 8. Change protected files or binaries

| | |
|---|---|
| Attack path | Edit `.py` files in an installed official build |
| Works? | Detected: reports say "Modified build" and name the files (tested on a real installed wheel) |
| Current protection | Signed SHA-256 manifest over every file, checked on every run |
| Remaining weakness | Editing a cached `.pyc` file that Python loads instead of the `.py` is not hashed (bytecode caches are skipped because they are made locally). Editing the checker itself (attack 7) |
| Mitigation | Install with `PYTHONDONTWRITEBYTECODE=1` and a read-only site-packages in sensitive deployments. The official Docker image keeps the package read-only for the non-root user |
| Severity | Low |
| Legal, ethical, practical? | Yes |

### 9. Get around offline validation

| | |
|---|---|
| Attack path | Keep using an expired key by setting the system clock back |
| Works? | Partly. A clock set back more than a day behind the latest time seen on that machine is noticed and reported as a license problem |
| Current protection | Latest-time record on every run with a key; 5-minute clock tolerance |
| Remaining weakness | A fresh machine or a deleted state folder has no record. A clock set back before the first run is not noticed |
| Mitigation | Use online licenses for customers where this matters: receipts expire on the server's clock |
| Severity | Low |
| Legal, ethical, practical? | Yes |

### 10. Get around online validation

| | |
|---|---|
| Attack path | Block the license server; fake the server; replay an old receipt |
| Works? | Blocking: works only for the grace period (default 14 days after the receipt ends), then the copy reports "activation required". Faking: no, receipts must be signed by Aevrin's activation key, and the server URL is inside the signed license. Replay: a receipt only works for its license, its installation, and until its expiry |
| Current protection | Signed receipts, signed activation URL, https only, grace period |
| Remaining weakness | The grace period is a deliberate window. A leak of the activation server's key lets someone mint receipts (but not licenses: keys are trusted per purpose) |
| Mitigation | Keep the activation key only on the server, behind TLS, with rate limits. Shorter grace periods for high-risk customers |
| Severity | Low |
| Legal, ethical, practical? | Yes |

### 11. Repackage the application

| | |
|---|---|
| Attack path | Rebuild and publish the package under another name, or with the notices removed |
| Works? | Technically yes, it is source code |
| Current protection | The license forbids commercial distribution and removing Required Notices. Trademarks forbid using the name. Official packages have Sigstore provenance from Aevrin's own workflow, so a repackaged one cannot carry it |
| Remaining weakness | Users who do not verify provenance can be fooled |
| Mitigation | Publish verification steps (licensing.md), takedown requests for public copies, trademark enforcement |
| Severity | Medium |
| Legal, ethical, practical? | Yes |

### 12. Build a changed Docker image

| | |
|---|---|
| Attack path | Change the code and build their own image, or add a layer on top of the official image |
| Works? | Yes for their own build |
| Current protection | A changed image has a different digest and no valid cosign signature or attestation from Aevrin's workflow. A layer that changes package files makes the scanner report "Modified build" |
| Remaining weakness | Same as attacks 3 and 7 for a fully rebuilt image |
| Mitigation | Customers run images by digest and check `cosign verify` (licensing.md). Admission controllers (for example Kyverno or Sigstore policy-controller) can require the signature in Kubernetes |
| Severity | Low |
| Legal, ethical, practical? | Yes |

### 13. Turn off required telemetry

| | |
|---|---|
| Attack path | Block the network to avoid reporting |
| Works? | Not applicable: there is no telemetry. The only network call is activation for online licenses, which is attack 10 |
| Current protection | Online licenses stop counting as licensed after the grace period without activation |
| Remaining weakness | None beyond attack 10 |
| Mitigation | If an agreement requires check-ins, use an online license with a short grace period |
| Severity | Low |
| Legal, ethical, practical? | Yes. No usage data is collected at all |

### 14. Fake an installation id

| | |
|---|---|
| Attack path | Use the same `AEVRIN_INSTALLATION_ID` on many machines so they count as one seat |
| Works? | Yes, the server cannot tell machines apart. The id is a random UUID on purpose, for privacy |
| Current protection | The server records the last time each id was seen and the version. Unusual patterns (one id seen from very many places) can be looked for on the server side |
| Remaining weakness | Seat counting is a fair-use measure, not proof |
| Mitigation | Contract terms with audit rights. Optional, if a customer agrees: bind receipts to a hardware-based id. Not done by default because it identifies machines |
| Severity | Medium |
| Legal, ethical, practical? | Hardware binding: legal with notice and consent, but less private. Default stays random |

### 15. Use one license on unlimited installations

| | |
|---|---|
| Attack path | Copy one license key to every machine |
| Works? | Offline licenses: yes, nothing counts them. Online licenses: no, the server refuses activations beyond `seats` (tested) |
| Current protection | Seat limits on online licenses, seat timeout after 45 days of silence, revocation |
| Remaining weakness | Offline licenses rely on the agreement only. Attack 14 |
| Mitigation | Issue online licenses by default for multi-seat customers. Keep offline licenses for air-gapped customers with audit terms |
| Severity | Medium for offline licenses, Low for online licenses |
| Legal, ethical, practical? | Yes |

## Summary

| # | Attack | Result | Severity |
|---|---|---|---|
| 1 | Remove branding | Possible on a changed copy; detected in official builds | Medium |
| 2 | Remove license validation | Gains nothing (nothing is blocked) | Low |
| 3 | Change license status | Files: blocked. Code: changed copy only | Medium |
| 4 | Forge a license | Blocked without the private key | None (Critical if the key leaks) |
| 5 | Change a license key | Blocked | None |
| 6 | Replace the public key | Changed copy only | Medium |
| 7 | Remove the integrity check | Changed copy only; verify from outside | Medium |
| 8 | Change protected files | Detected | Low |
| 9 | Bypass offline validation | Clock rollback mostly detected | Low |
| 10 | Bypass online validation | Grace period only | Low |
| 11 | Repackage | Legal and provenance | Medium |
| 12 | Changed Docker image | No valid signature | Low |
| 13 | Disable telemetry | No telemetry exists | Low |
| 14 | Fake installation id | Possible | Medium |
| 15 | Unlimited installations | Blocked for online licenses | Medium (offline) |

## What we do not do

- No hidden behavior: no secret watermarks, no silent data collection, no "phone home" for
  unlicensed copies.
- No destructive actions: a license problem never deletes files, corrupts reports, or stops a
  scan halfway.
- No obfuscation of the source. It would make the code harder to review (this is a security tool)
  while a determined attacker could still undo it.

## Further hardening, if needed later

| Option | What it adds | Cost |
|---|---|---|
| Compiled commercial builds (for example Nuitka) | Source is not shipped to commercial customers; much harder to change | Build pipeline per platform; harder debugging |
| Hardware-bound activation (opt-in) | Stops installation id sharing | Less private; needs consent |
| Signed reports (per-installation keys issued by the server) | A report can prove it came from a licensed, unchanged installation | Server and key management work |
| Kubernetes admission policy | Only Aevrin-signed images run | Customer-side setup |
