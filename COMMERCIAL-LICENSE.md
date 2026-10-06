# Commercial license

Aevrin MCP Scanner is free for **noncommercial** use under the
[PolyForm Noncommercial License 1.0.0](LICENSE). Any **commercial** use needs a
commercial license from Aevrin.

This page explains who needs a commercial license and how licensing works. It is
not itself a contract. The commercial terms are in a written agreement that you
sign with Aevrin.

## Contact

<!-- LICENSING-CONTACT: replace the next line with your sales email or web page before publishing a release. -->
Commercial licensing contact: **not set yet**

## Do I need a commercial license?

You need one if you use the software for any purpose with an anticipated
commercial application. For example:

- scanning MCP servers at or for a company, including internal use and CI pipelines,
- scanning servers for paying customers, or as part of a paid audit or consulting service,
- offering the scanner, or its results, as part of a hosted service or a product,
- shipping the scanner inside another product.

You do **not** need one for personal study, research for the benefit of public
knowledge, hobby projects, or use by the noncommercial organizations named in
the [LICENSE](LICENSE). If you are unsure, ask before you use it commercially.

## What a commercial license gives you

The exact terms are in your agreement. A standard agreement covers:

| Topic | Standard term |
|---|---|
| Use | Commercial use by the licensed organization, for the term of the license |
| Seats | A number of installations, counted by installation ID when the license uses online activation |
| Editions | `commercial` (production), `development` (non-production), `evaluation` (time limited) |
| Versions | Every release up to the major version named in the license key |
| Hosted use | Only when the agreement grants it in writing |
| Notices | Copyright, license, and branding notices must stay in place |
| License keys | The license key mechanism must not be bypassed, disabled, or changed |
| Support | As stated in the agreement |

## How you get and activate a license

1. Contact Aevrin (see above) and sign the commercial agreement.
2. You receive a license key: a single line that starts with `AEVRIN1.`, or a `.lic`
   file that holds it. The key is signed by Aevrin, so it cannot be edited.
3. Activate it on each machine or container:

   ```bash
   mcp-scanner license activate path/to/aevrin.lic      # or paste the key instead of a path
   mcp-scanner license status
   ```

   In Docker and CI, pass it at runtime instead. See [docs/licensing.md](docs/licensing.md).

4. Every report now says who the copy is licensed to.

Keep your license key private, like a password. It identifies your organization.
