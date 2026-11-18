# Sentinel Guard threat database

Builds the signed threat-intelligence bundle used by the Sentinel Guard Android app and
publishes it, together with the privacy policy, to GitHub Pages:

- `https://ahmetselimergin.github.io/sentinelguard/db/` — signed bundle (rebuilt daily)
- `https://ahmetselimergin.github.io/sentinelguard/privacy/` — privacy policy

Data: [MalwareBazaar](https://bazaar.abuse.ch/) (Android-relevant sample hashes) and
[URLhaus](https://urlhaus.abuse.ch/) (hosts serving malware), both by abuse.ch, used under
their terms of use. `manifest.json` is signed with ECDSA P-256; the app rejects any bundle
whose signature or file hashes don't verify.
