# Licensing, license keys, and signed releases

This page explains how Aevrin MCP Scanner is licensed, how commercial license keys work, how
releases are signed, and what the software checks. It is written for developers who are new to
the code. The attacks and limits are in [licensing-threat-model.md](licensing-threat-model.md).

> **Reality check.** Anyone who has the full source code can change it and build their own
> version. No check inside the program can make that impossible. The protection here has layers:
> the license makes misuse illegal, signatures make forgery detectable, and the checks make
> misuse visible and more work. Nothing here is "unremovable", and we never claim it is.

| Layer | What it does | Where |
|---|---|---|
| Legal | The license and the commercial agreement say what is allowed | `LICENSE`, `NOTICE`, `COMMERCIAL-LICENSE.md`, `TRADEMARKS.md` |
| Cryptographic | License keys, activation receipts, and release manifests are signed with Ed25519 | `src/mcp_scanner/licensing/` |
| Technical | Every run checks the license and the build, and every report shows the result | `licensing/status.py`, the reporters |
| Supply chain | Releases have checksums, an SBOM, signed provenance, and a signed Docker image | `.github/workflows/release.yml` |
| Operational | Online licenses activate with Aevrin's server, which counts seats and can revoke | `src/scripts/licensing/license_server.py` |
| Detection | Changed builds name themselves in every report | `licensing/integrity.py` |

## 1. The license

**PolyForm Noncommercial License 1.0.0** (SPDX `PolyForm-Noncommercial-1.0.0`), plus a separate
paid commercial license. It is a source-available license, not an open source license.

### Why this license

The goal is to stop free commercial use while keeping the code readable and usable for
noncommercial users. We compared the common choices:

| License | Free commercial use | Change and share | Notices protected | License key protected | Hosted (SaaS) use | OSI approved | Notes |
|---|---|---|---|---|---|---|---|
| **PolyForm Noncommercial** (chosen) | No | Yes, noncommercial only | "Required Notice:" lines must stay | Through the commercial agreement | Needs a commercial license | No | Plain-language, written by licensing lawyers |
| PolyForm Strict | No | No changes, no sharing | Yes (no changes at all) | Yes (no changes at all) | Needs a commercial license | No | Strongest, but no forks or patches even for hobby use |
| Elastic License 2.0 | **Yes** | Yes | Yes, explicitly | Yes, explicitly | Only managed services are banned | No | Does not stop free commercial use |
| Business Source License 1.1 | Non-production only | Yes | Must show the license | No | Depends on the grant | No | Each version becomes open source after at most 4 years |
| Functional Source License | **Yes**, except competing use | Yes | Basic | No | Only competing use is banned | No | Becomes Apache or MIT after 2 years |
| SSPL | Yes | Yes | Basic | No | Forces the whole service to be open | No | Built for databases offered as a service |
| MIT, Apache 2.0 | Yes | Yes | Copyright notice only | No | Yes | Yes | Open source, no restriction on commercial use |

Only the two PolyForm licenses stop free commercial use. Noncommercial was chosen over Strict so
that people can still study, fix, and share the code for noncommercial work.

### What you may and may not do

| | Noncommercial user (no key) | Commercial user (with a commercial license) |
|---|---|---|
| Use the scanner | Yes, for noncommercial purposes | Yes, as the agreement says |
| Change the code | Yes, for noncommercial purposes | As the agreement says |
| Share copies | Yes, with LICENSE and every "Required Notice:" line | As the agreement says |
| Use it at or for a company, or for paying customers | **No** | Yes |
| Offer it as a hosted service | **No** | Only if the agreement grants it |
| Remove the copyright, license, or branding notices | **No** | **No** |
| Bypass or disable the license key checks | Not relevant (no key needed) | **No** (agreement) |
| Use the Aevrin name for your own product | **No** (see TRADEMARKS.md) | **No**, unless agreed |

Every source file starts with:

```python
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
```

## 2. Branding

Branding comes from one module, `src/mcp_scanner/branding.py`, and shows up in:

| Place | What it shows |
|---|---|
| `mcp-scanner --help` | Copyright and the noncommercial notice |
| `mcp-scanner version` | Name, version, copyright, license status, build status |
| Every console, Markdown, JSON, and SARIF report | Name, version, copyright, license status, build status (`product` block) |
| HTTP requests to remote MCP servers | `User-Agent: aevrin-mcp-scanner/<version>` |
| Package metadata | `License-Expression: PolyForm-Noncommercial-1.0.0`, LICENSE and NOTICE inside the wheel |
| Docker image | OCI labels (`vendor`, `licenses`, `version`, `revision`), LICENSE and NOTICE in `/usr/share/doc` |

Reports get the block in two independent ways: the scan engine adds it, and every reporter adds it
again if it is missing. Removing one line does not remove the branding. CI checks that both are
still there.

Nothing is hidden: no invisible watermarks, and no tracking.

## 3. Commercial license keys

### What a license key is

A license key is one line of text that starts with `AEVRIN1.`:

```text
AEVRIN1.<payload>.<signature>
```

- **payload**: base64url JSON with the license details (below).
- **signature**: an Ed25519 signature by Aevrin over `AEVRIN1.<payload>`.

Ed25519 is a modern public-key signature scheme (RFC 8032). Aevrin signs with a **private key**
that never leaves Aevrin. The scanner contains only the matching **public key**, which can check
a signature but cannot make one. If one character of the payload changes, the signature no longer
matches, and the key is rejected.

| Field | Meaning |
|---|---|
| `lid` | License id, for example `L-2026-5E13620C` |
| `licensee` | The organization it is issued to |
| `edition` | `commercial` (production), `development` (non-production), `evaluation` (trial) |
| `features` | Entitlements, for example `["*"]` for everything |
| `iat`, `nbf`, `exp` | Issued at, valid from, expires at (Unix seconds). No `exp` means perpetual |
| `max_major` | Newest major version covered (1 means every 1.x release) |
| `online`, `activation`, `seats`, `grace_days` | Online activation settings (section 4) |
| `kid` | Which Aevrin key signed it |
| `product` | Always `aevrin-mcp-scanner` |

### How the scanner checks a key (offline)

1. Find the key: `AEVRIN_LICENSE` (the key itself), then `AEVRIN_LICENSE_FILE` (a path), then
   `~/.aevrin-mcp-scanner/license.lic` (saved by `mcp-scanner license activate`).
2. Check the signature with the public key named by `kid`. Each public key is trusted for **one
   purpose only**: a license key must be signed by a license key, not by the release key or the
   activation server's key.
3. Check the product, the dates (5 minutes of clock tolerance), and the version.
4. Notice a clock set back in time: the latest time seen is recorded on every run with a key, and
   a clock more than a day behind it is not trusted.
5. For online licenses, check the activation receipt (section 4).

### What happens without a valid key

Nothing is blocked. That is a deliberate choice: the LICENSE allows noncommercial use without a
key, and the scanner cannot know whether a given run is commercial. Instead, the result is shown:

| State | Every report says |
|---|---|
| No key | `Licensed for noncommercial use only (PolyForm Noncommercial 1.0.0). Commercial use requires a commercial license from Aevrin.` |
| Valid | `Licensed to ACME Corp (commercial license L-2026-0042, valid until 2027-10-06).` |
| Expired, wrong version, forged, revoked, clock problem | `License problem: <reason>. Running under the noncommercial terms.` plus the notice |

The `features` field is checked with `License.allows("name")`. No feature is gated today. If
Aevrin later decides to gate a feature, this is where it is done, and the license key already
carries the entitlements.

## 4. Online activation (only for licenses marked `online`)

Offline licenses never contact anyone. Online licenses activate each installation with Aevrin's
license server, which lets Aevrin count seats and revoke a license.

```text
scanner  -- POST <activation URL>/v1/activations {license key, installation id, version} -->  server
scanner  <-- {receipt} (signed by the activation key, valid 30 days) --------------------  server
```

- The **installation id** is a random UUID made on first use (`~/.aevrin-mcp-scanner/installation.json`).
  It is not derived from the machine, the user, or the network.
- The **receipt** is saved and checked offline on every run. It names the license and the
  installation, so copying it to another machine does not work. It is renewed when less than
  7 days are left.
- When the server cannot be reached, the license keeps working for `grace_days` (default 14)
  after the receipt ends. Reports say so. After that, the copy falls back to the noncommercial notice.
- The server checks the license key's signature itself, counts installations per license, frees
  seats not seen for 45 days, and answers 410 for revoked licenses.
- The activation URL is inside the signed license key, so it cannot be redirected to a fake server.
  Only `https://` URLs are accepted (plus `http://127.0.0.1` and `http://localhost` for testing).

### What is sent, and nothing else

| Sent | Why |
|---|---|
| The license key | So the server can check it |
| The installation id (random UUID) | To count seats |
| The scanner version | To answer for the right version |

**There is no telemetry.** Nothing about scans, targets, servers, findings, files, or users is
ever sent. Offline licenses and unlicensed copies send nothing at all.

## 5. Build integrity

Each official release carries `mcp_scanner/_release/manifest.json`: the SHA-256 hash of every
file in the package, signed with Aevrin's **release** key. On every run the scanner checks:

| Result | Meaning | Shown in reports |
|---|---|---|
| `official` | The signature is valid and every file matches | nothing extra |
| `modified` | The signature is invalid, or a file was changed, removed, or added | `Modified build: not an official Aevrin release (...)` |
| `development` | No manifest: a source checkout or a local build | `Development build: not an official release.` |

A plain checksum only says "these bytes changed". The signature says the list of hashes came from
Aevrin, so someone who changes a file cannot simply write new hashes. Check a copy yourself:

```bash
mcp-scanner license verify-build        # exit 1 if modified
```

## 6. Signed releases and the supply chain

The release workflow (`.github/workflows/release.yml`) runs for version tags only:

1. Release checks: license text, notices, contact, keys, dependency licenses.
2. Sign the integrity manifest with the release key from the CI secret store.
3. Build the wheel and sdist with `SOURCE_DATE_EPOCH` set, for reproducible timestamps.
4. Install the wheel and require `mcp-scanner license verify-build` to say `official`.
5. Publish `SHA256SUMS`, a CycloneDX SBOM, and signed SLSA build provenance and SBOM attestations
   (Sigstore, through GitHub's `actions/attest`).
6. Publish to PyPI with Trusted Publishing, which also creates PEP 740 attestations. No API token.
7. Build the Docker image, sign it by digest with cosign (keyless, GitHub OIDC), and attest it.

### How a customer verifies a release

```bash
sha256sum -c SHA256SUMS                                          # files match the checksums
gh attestation verify aevrin_mcp_scanner-1.0.0-py3-none-any.whl --repo Aevrin-ai/mcpScanner
cosign verify ghcr.io/aevrin-ai/mcpscanner@sha256:<digest> \
  --certificate-identity-regexp 'https://github.com/Aevrin-ai/mcpScanner/.github/workflows/release.yml@refs/tags/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
mcp-scanner license verify-build                                 # the installed copy is unchanged
```

Always run images by digest (`@sha256:...`), not only by tag: a tag can be moved, a digest cannot.

## 7. Docker and CI

Never put a license key or any signing key into an image. Give the license at run time:

```bash
# A file mounted read-only where the image looks for it (/run/secrets/aevrin_license)
docker run --rm -v "$PWD/aevrin.lic:/run/secrets/aevrin_license:ro" aevrin-mcp-scanner scan tools.json
# docker compose: uncomment the "secrets:" lines in compose.yaml (a real Docker secret)

# Or a variable, for example from your CI secret store
docker run --rm -e AEVRIN_LICENSE="$AEVRIN_LICENSE" aevrin-mcp-scanner scan tools.json
```

- Containers start fresh, so an online license needs a **stable installation id** per deployment:
  set `AEVRIN_INSTALLATION_ID` to a UUID you keep (one per deployment, not one per run). Each
  different id uses a seat.
- In CI, store the key as a masked secret and pass it as `AEVRIN_LICENSE`. Reports from CI then
  show the licensee.

## 8. Keys

| Key | Signs | Kept where | Public key |
|---|---|---|---|
| `license-*` | License keys | Offline, by Aevrin (password manager or hardware key) | `licensing/keys.py` |
| `release-*` | Release manifests | CI secret `AEVRIN_RELEASE_SIGNING_KEY` in a protected environment | `licensing/keys.py` |
| `activation-*` | Activation receipts | Only on the license server | `licensing/keys.py` |

```bash
# Make a key pair (refuses to write inside the repository). Set AEVRIN_KEY_PASSPHRASE to encrypt it.
python src/scripts/licensing/keygen.py --purpose license --out ~/.aevrin-signing
```

- **Rotate**: make a new key, add its public line to `keys.py`, sign new licenses with it, and keep
  the old line until everything it signed has expired.
- **Revoke a leaked key**: remove its line from `keys.py` and release a new version. Everything it
  signed stops being trusted in that version.

## 9. For Aevrin: issuing a license

```bash
python src/scripts/licensing/issue_license.py --key ~/.aevrin-signing/license-2026-10.key.pem \
  --licensee "ACME Corp" --edition commercial --days 365 --features "*" --max-major 1 --out acme.lic

# Online license with 10 seats:
python src/scripts/licensing/issue_license.py --key ... --licensee "ACME Corp" --days 365 \
  --online --activation https://license.example.com --seats 10 --out acme.lic

# Reference activation server (put a TLS proxy in front of it):
python src/scripts/licensing/license_server.py --key ~/.aevrin-signing/activation-2026-10.key.pem --db licenses.sqlite
python src/scripts/licensing/license_server.py --db licenses.sqlite --revoke L-2026-0042
```

The issue script checks every new key the same way the scanner will before it prints it.

## 10. For customers: getting and activating a license

1. Contact Aevrin (see [COMMERCIAL-LICENSE.md](../COMMERCIAL-LICENSE.md)) and sign the agreement.
2. You receive a key (`AEVRIN1....`) or a `.lic` file. Keep it private.
3. Activate it:

   ```bash
   mcp-scanner license activate acme.lic
   mcp-scanner license status
   ```

   In Docker or CI, pass it at run time instead (section 7).
4. `mcp-scanner license deactivate` removes it from this user's settings, for example before you
   move a seat to another machine.

## 11. For developers: changing protected code

Some files are protected: the licensing package, `branding.py`, the legal texts, the CI workflows,
and the license tools. Their hashes are pinned in `src/scripts/protected-files.sha256`, and
`.github/CODEOWNERS` requires the owners' review.

1. Make your change.
2. Run `python src/scripts/check_licensing.py`. It names every protected file you changed.
3. If the change is intended, run `python src/scripts/check_licensing.py --update-pins` and commit
   the updated pin file in the same pull request. Reviewers see exactly what changed.

A source checkout always reports itself as a `development` build. That is expected.
