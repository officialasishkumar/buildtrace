# Install census: who serves popular packages, and what installs fetch outside the registry

Each package was installed alone, in a fresh container with an empty cache, under `buildtrace run`. Host names come from TLS SNI, DNS answers and HTTP Host headers; operators and countries from iptoasn.com. DNS lookups are not counted as downloads.

## npm-installscripts

25 installs traced (1 exited non-zero), 0 produced no report; 903.6 MB downloaded in total.

- **9 of 25** installs contacted a host other than the registry (registry.npmjs.org, registry.yarnpkg.com).
- **0** used plaintext HTTP for at least one connection.
- Bytes by operator: Cloudflare 59%, Google 37%, Fastly 2%, Amazon.com 1%, Microsoft Corporation 0%
- Bytes by country of network registration: US 100%

| package | host contacted outside the registry | bytes | operator | cc | process | plaintext |
|---|---|---:|---|---|---|---|
| puppeteer | storage.googleapis.com | 320.9 MB | Google | US | node |  |
| cypress | cdn.cypress.io | 209.8 MB | Cloudflare | US | node |  |
| canvas | release-assets.githubusercontent.com | 19.5 MB | Fastly | US | node |  |
| chromedriver | storage.googleapis.com | 15.3 MB | Google | US | node |  |
| ngrok | bin.equinox.io | 10.3 MB | Amazon.com | US | node |  |
| node-sass | nodejs.org | 9.6 MB | Cloudflare | US | node |  |
| node-pty | nodejs.org | 9.5 MB | Cloudflare | US | node |  |
| sqlite3 | release-assets.githubusercontent.com | 1.1 MB | Fastly | US | node |  |
| re2 | release-assets.githubusercontent.com | 474.3 KB | Fastly | US | node |  |
| canvas | github.com | 12.3 KB | Microsoft Corporation | US | node |  |
| sqlite3 | github.com | 11.8 KB | Microsoft Corporation | US | node |  |
| re2 | github.com | 11.8 KB | Microsoft Corporation | US | node |  |
| cypress | download.cypress.io | 11.1 KB | Cloudflare | US | node |  |
| chromedriver | googlechromelabs.github.io | 10.0 KB | Fastly | US | node |  |
| node-sass | github.com | 7.0 KB | Microsoft Corporation | US | node |  |

## npm-top300

300 installs traced (1 exited non-zero), 0 produced no report; 185.4 MB downloaded in total.

- **0 of 300** installs contacted a host other than the registry (registry.npmjs.org, registry.yarnpkg.com).
- **0** used plaintext HTTP for at least one connection.
- Bytes by operator: Cloudflare 100%
- Bytes by country of network registration: US 100%

## pypi-top200

200 installs traced (0 exited non-zero), 0 produced no report; 727.8 MB downloaded in total.

- **1 of 200** installs contacted a host other than the registry (files.pythonhosted.org, pypi.org).
- **0** used plaintext HTTP for at least one connection.
- Bytes by operator: Fastly 100%, Cloudflare 0%
- Bytes by country of network registration: US 100%

| package | host contacted outside the registry | bytes | operator | cc | process | plaintext |
|---|---|---:|---|---|---|---|
| typing-extensions | 104.16.11.34 | 368 B | Cloudflare | US |  |  |

