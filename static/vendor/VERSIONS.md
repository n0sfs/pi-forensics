# Vendored front-end libraries

Served locally so an offline station or LAN gets a styled, working UI (Eric's decision 2026-11-20; they used to load from a public CDN, with Chart.js unpinned).
Copied unmodified from the npm packages (npm verified each tarball's integrity hash). Source maps left out.

| Library | Version | Files |
|---|---|---|
| Bootstrap | 5.3.0 | bootstrap-5.3.0/css/bootstrap.min.css, js/bootstrap.bundle.min.js |
| Bootstrap Icons | 1.10.0 | bootstrap-icons-1.10.0/bootstrap-icons.css, fonts/ |
| Chart.js | 4.4.1 | chart.js-4.4.1/chart.umd.js |
| Leaflet | (existing) | leaflet/ |
| vis-network | (existing) | vis-network/ |

To upgrade one, replace its folder with the new version's files under a new versioned folder name and update templates/index.html and templates/login.html.

SHA-256 (first 16 hex): bootstrap.min.css 7f1d37f0d90b6385, bootstrap.bundle.min.js aa53d582f97eb594, bootstrap-icons.css 0695565c51d65e05, bootstrap-icons.woff2 eba8243051339456, chart.umd.js 74401d738dd3e03e.
