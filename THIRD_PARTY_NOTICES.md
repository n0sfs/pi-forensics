# Third-Party Notices

Pi Forensics Suite's own original source code — the Flask application (`app.py`, `core/`, `routes/`),
the frontend (`templates/`, `static/js/main.js`), the setup/deployment scripts (`install.py`,
`uninstall.py`, `systemd/`, `nginx/`), and everything else written for this project — is licensed
under the Apache License, Version 2.0 (relicensed from GPLv3 on 2026-09-04 - see the maintainer's
note at the top of [LICENSE](LICENSE)). See [LICENSE](LICENSE) for the full text.

**None of the license grants below apply to this project's own code, and this project's Apache-2.0
license does not apply to any of the tools, libraries, or assets listed below.** To do its job, the
station installs, imports, vendors, or loads a large number of pre-existing third-party forensic
tools, Python libraries, and frontend assets. Each one keeps its own original license, exactly as its
own authors published it. This project does not relicense any of it, and — with the handful of
vendored exceptions noted below, which are bundled unmodified at a pinned version or commit — does
not modify any of it either.

## Why this doesn't affect this project's own Apache-2.0 license

- **System tools** (installed via `apt-get`) are launched as separate operating-system processes via
  Python's `subprocess` module — never compiled into, statically linked with, or dynamically loaded
  by this project's own code. Subprocess invocation isn't linking under any of these licenses (this
  is the same "mere aggregation" case GPL itself describes in its own section 5, for the many system
  tools below that are themselves GPL-licensed): running a separately-licensed tool as a subprocess
  doesn't require the tool to adopt this project's license, and doesn't require this project to adopt
  the tool's license either - regardless of which permissive or copyleft terms either side uses.
- **Python packages** (installed via `pip install -r requirements.txt`) are mostly imported directly
  into the app's own process. Every one of them is licensed under a permissive license (MIT, BSD,
  Apache-2.0, PSF), a copyleft "library" license explicitly designed to be linked from any codebase
  regardless of that codebase's own license (LGPL-3.0), or a bespoke permissive grant (the DC3
  SQLite Dissect license) — every one of those terms is compatible with a permissively-licensed host
  application. A few Python packages are wrapped as subprocesses rather than imported (`mvt`,
  `volatility3`, `sqlite-dissect`, `wa-crypt-tools`) for exactly the same "mere aggregation" reason as
  the system tools above.
- **Vendored tools** are fetched at install time straight from the upstream project's own GitHub
  repository, pinned to a specific tagged release or commit, and run as a separate process — same
  reasoning as the system tools.
- **Frontend libraries** are loaded from a public CDN at page-load time, or (Leaflet only) vendored as
  an unmodified local copy under `static/vendor/leaflet/` for stations without internet access. All
  four are permissively licensed.

If you redistribute, deploy, modify, or build on this station, you're responsible for complying with
each of the licenses below individually, in addition to this project's own Apache-2.0 license. This document is
maintained on a best-effort basis alongside `requirements.txt` and `install.py` — if either changes,
this list should too (see the pointer comments near the top of each file).

## System tools (installed via `apt-get`, run as subprocesses)

| Tool | License | Notes |
|---|---|---|
| dc3dd | GPL-3.0-or-later | |
| dcfldd | GPL-2.0-or-later | |
| ewf-tools / libewf-dev | LGPL-3.0-or-later | libyal project |
| gddrescue (GNU ddrescue) | GPL-2.0-or-later | |
| afflib-tools | Mixed — LGPL-2.1 (core library), BSD-3/4-Clause (most CLI tools), a few smaller components under other permissive terms | |
| smartmontools | GPL-2.0-or-later | |
| cifs-utils | GPL-3.0 | |
| nfs-common | Mixed — mostly GPL-2.0, some BSD-2/3-Clause | |
| smbclient (Samba) | GPL-3.0-or-later | some component libraries are LGPL-3.0-or-later |
| sshfs | GPL-2.0-only | |
| chromium-browser | BSD-3-Clause (Google's own code) | plus many bundled third-party components, each under its own license |
| libimobiledevice-utils | LGPL-2.1-or-later | some bundled CLI tools are GPL-2.0-or-later |
| usbmuxd | GPL-2.0-or-later / GPL-3.0-or-later (daemon) | `libusbmuxd` itself is LGPL-2.1-or-later |
| adb (Android platform-tools) | Apache-2.0 | Android Open Source Project |
| nginx | BSD-2-Clause | |
| openssl | Apache-2.0 (v3.0 and later) | |
| wvkbd | GPL-3.0-only | |
| testdisk / photorec | GPL-2.0-or-later | CGSecurity |
| libimage-exiftool-perl (ExifTool) | GPL-1.0-or-later OR Artistic-1.0-Perl (dual, "same terms as Perl itself") | Phil Harvey |
| sleuthkit | Mixed — core library historically CPL-1.0 / IPL-1.0, a few bundled tools GPL-2.0-only | not a single blanket license; see note below |
| binwalk | MIT | |
| clamav / clamav-freshclam | GPL-2.0-only | |
| hashdeep | Public Domain (US Government work) | one bundled Tiger-hash routine is GPL-2.0-only |
| extundelete | GPL-2.0-only | |
| foremost | Public Domain (US Government work) | Debian packaging and a couple of contributed files are separately GPL-2.0-or-later |
| scalpel | Apache-2.0 (current sleuthkit/scalpel fork, what Debian ships) | |
| dislocker | GPL-2.0-or-later | |
| acl (setfacl/getfacl) | GPL-2.0-or-later (CLI) | `libacl1` itself is LGPL-2.1-or-later |
| cryptsetup-bin | GPL-2.0-or-later (CLI) | `libcryptsetup` itself is LGPL-2.1-or-later |
| pcscd / libpcsclite-dev | Custom BSD-3-Clause-style license (PC/SC Lite project) | **not** GPL — see note below |
| pcsc-tools | GPL-2.0-or-later | a separate package from pcscd/libpcsclite-dev above |
| exfatprogs | GPL-2.0-or-later | |
| tesseract-ocr | Apache-2.0 | |
| ffmpeg | GPL-2.0-or-later, as built by Debian (`--enable-gpl`, no `--enable-nonfree`) | upstream's own default build (no `--enable-gpl`) is LGPL-2.1-or-later |

## Python packages (installed via `pip install -r requirements.txt`)

| Package | License | Notes |
|---|---|---|
| Flask | BSD-3-Clause | |
| gunicorn | MIT | |
| psutil | BSD-3-Clause | |
| reportlab | ReportLab's own BSD-style license | |
| mvt (Mobile Verification Toolkit) | **MVT License 1.1** (custom, MPL-2.0-derived) | not plain MPL — see note below |
| pytsk3 | Apache-2.0 | Python bindings for the Sleuth Kit; the wheel bundles Sleuth Kit's and talloc's own license text |
| cryptography | Apache-2.0 OR BSD-3-Clause (dual — licensee's choice) | |
| volatility3 | **Volatility Software License (VSL) v1.0** (custom) | not a standard OSI license — see note below |
| python-registry | Apache-2.0 | |
| python-evtx | Apache-2.0 | |
| LnkParse3 | MIT | |
| olefile | BSD-2-Clause-style | incorporates permissively-licensed code from PIL/Pillow's OleFileIO |
| Markdown (Python-Markdown) | BSD-3-Clause | |
| yara-python | Apache-2.0 | the underlying YARA C library itself is BSD-3-Clause |
| libscca-python | LGPL-3.0-or-later | libyal project |
| defusedxml | PSF License 2.0 | |
| sqlite-dissect | **DC3 SQLite Dissect Open Source License** (custom, US DoD-authored) | permissive grant, not an OSI-catalogued license — see note below |
| androguard | Apache-2.0 | |
| wa-crypt-tools | GPL-3.0-or-later | |
| lief | Apache-2.0 | |
| dumpstate-py | Apache-2.0 | not on PyPI, installed via `pip install git+...` pinned to a commit SHA |
| analyzeMFT | MIT | |
| libpff-python | LGPL-3.0-or-later | libyal project |
| py-tlsh | Apache-2.0 OR BSD (dual) | fuzzy-hashing algorithm originally by Trend Micro |
| libvshadow-python | LGPL-3.0-or-later | libyal project |
| libesedb-python | LGPL-3.0-or-later | libyal project |

## Vendored tools (fetched at install time, pinned to a tag/commit, run unmodified as a subprocess)

| Tool | License | Copyright | Notes |
|---|---|---|---|
| mquire | Apache-2.0 | Trail of Bits, Inc. | pinned to tag `1.4.1`, built from source at install time |
| ALEAPP | MIT | Alexis Brignoni | pinned to a commit, own isolated Python environment |
| iLEAPP | MIT | Alexis Brignoni | pinned to a commit, own isolated Python environment |
| pysim | GPL-2.0-or-later | Harald Welte and the Osmocom project | pinned to a commit, own isolated Python environment |
| UAC (Unix-like Artifacts Collector) | Apache-2.0 | Thiago Canozzo Lahr and contributors | pinned to tag `v3.3.0` |
| AVML | MIT | Microsoft Corporation | pinned to tag `v0.20.0`, prebuilt release binary |
| WinPmem | Apache-2.0 | Michael Cohen / Velocidex Enterprises | pinned release asset, prebuilt binary |

## Frontend libraries

| Library | License | Notes |
|---|---|---|
| Bootstrap 5 (`v5.3.0`) | MIT | loaded from a jsdelivr CDN |
| Bootstrap Icons (`v1.10.0`) | MIT | loaded from a jsdelivr CDN |
| Chart.js | MIT | loaded from a jsdelivr CDN |
| Leaflet (`v1.9.4`) | BSD-2-Clause | vendored locally under `static/vendor/leaflet/` so the map viewer still works on a station with no internet access |

## Licenses worth reading closely

A few of the above are **not** standard OSI-approved open-source licenses, or are easy to
mischaracterize. If you're deploying, redistributing, or building on this station, read these
directly rather than assume they behave like a familiar GPL/MIT/BSD grant:

- **MVT (Mobile Verification Toolkit)** — the "MVT License 1.1" is an MPL-2.0-derived license that
  adds a binding requirement (section 3.0) to obtain the informed consent of the device or data owner
  before using MVT against their data. That's a real usage restriction beyond a normal copyleft term,
  not just a relabeled MPL-2.0. See
  [mvt-project/mvt's LICENSE](https://github.com/mvt-project/mvt/blob/main/LICENSE).
- **Volatility 3** — the "Volatility Software License (VSL) v1.0" is a custom, non-standard hybrid
  copyleft license with an unusually broad definition of "Additions" (software that executes on or
  parses the tool's own output can itself be considered a covered addition). See
  [volatilityfoundation/volatility3's LICENSE.txt](https://github.com/volatilityfoundation/volatility3/blob/develop/LICENSE.txt).
- **sqlite-dissect** — the "DC3 SQLite Dissect Open Source License" was issued by the US Department of
  Defense Cyber Crime Center under statutory authority (Pub. L. 113-66, section 801(b)). It's a
  permissive grant in practice, but it isn't an OSI-catalogued license and its exact terms are worth
  reading rather than assuming.
- **hashdeep and foremost** — both originated as US federal government works and are Public Domain in
  the United States (17 U.S.C. section 105); their legal status outside the US is less settled.
  foremost's Debian packaging and a couple of its contributed files are separately GPL-2.0-or-later.
- **The Sleuth Kit** — its core library has historically been dual-licensed under the Common Public
  License 1.0 / IBM Public License 1.0 (both OSI-approved, but GPL-*incompatible* for direct linking);
  a few of its bundled command-line tools are separately GPL-2.0-only. This station only ever invokes
  `sleuthkit` as installed system binaries via `subprocess`, or through `pytsk3`'s own Apache-2.0
  Python bindings — it never links against `libtsk` directly.
- **pcscd / libpcsclite-dev (PC/SC Lite)** — a custom BSD-3-Clause-style license written by the
  project's own maintainer, not GPL. Don't assume it inherits `pcsc-tools`' GPL-2.0-or-later license
  just because the two ship together and are used for the same feature.

---

*This document reflects a best-effort, point-in-time survey of each dependency's license as published
by its own upstream project at the time this document was written. It is not legal advice. If you rely
on this list for a compliance decision, verify the current license directly against each project's own
repository.*
