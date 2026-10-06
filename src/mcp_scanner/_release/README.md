# Release manifest

The release workflow writes `manifest.json` and `manifest.sig` here before it builds a
release (src/scripts/licensing/sign_release.py). They list the SHA-256 hash of every
file in the package, signed with Aevrin's release key.

Do not commit those two files. Without them, a copy reports itself as a development build.
