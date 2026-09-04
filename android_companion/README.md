# pif-companion (Android)

Source for `pif-companion.apk`, the companion app the Mobile Forensics tab's
"Companion-App Extraction (Advanced)" section installs onto a connected
Android device for four genuinely separate, additive extraction actions -
SMS (`execution_worker_android_companion_sms()`, `core/android_companion_
sms_utils.py`), Contacts/Call Log (`execution_worker_android_companion_
contacts_calllog()`, `core/android_companion_contacts_calllog_utils.py`),
and Calendar events + attendees (`execution_worker_android_companion_
calendar()`, `core/android_companion_calendar_utils.py`), all three in
`routes/mobile.py` - see any module's own docstring for the full picture on
why each is needed.

## What it is

Four tiny `ContentProvider` classes (`ContactsProvider.java`/
`CallLogProvider.java`/`SmsProvider.java`/`CalendarProvider.java`) - each a
pure authority-rewriting relay onto a real system provider
(`com.android.contacts`/`call_log`/`sms`/`com.android.calendar`), restricted
to `SHELL_UID` callers only. Contacts/Call Log were hand-built first
(2026-09-04), mirroring the exact same relay-provider design already proven
by [github.com/gonodono/adbsms](https://github.com/gonodono/adbsms) (MIT) -
its real source was cloned and read to confirm the pattern before this app
was written, since no equivalent existing open-source relay tool was found
for Contacts/Call Log (2026-09-04 survey - the closest candidates were
either UI-driven dev tools with no headless build, or long-archived
pre-runtime-permission-model tools with no LICENSE file).

SMS support was folded into this same app the same day (`SmsProvider.java`,
versionCode 2/versionName 1.0.2), replacing what had originally been a
separately vendored third-party dependency (adbsms.min itself) - once this
app's own build toolchain (Google's official `android` CLI, below) was
proven working and adbsms's own real manifest requirements for
`android.app.role.SMS` eligibility were already fully understood from
building the first two providers, there was no remaining reason to maintain
two vendored Android apps for a mechanism this project now fully owns and
builds itself. `SmsProvider`'s own relay logic and `android.app.role.SMS`
manifest requirements (6 permissions + 4 unbacked component stubs, gated
via `tools:ignore="MissingClass"` on the `<application>` tag) were ported
directly from adbsms's real, still-cloned source.

Calendar support (`CalendarProvider.java`, versionCode 3/versionName 1.0.3)
was added the same day, once the user asked to keep extending the companion
app's own reach - a single plain `READ_CALENDAR` runtime permission, no
role-assumption dance needed at all. Every real column-name string and
integer status/relationship/type constant `core/android_companion_calendar_
utils.py` relies on was independently confirmed live against Google's own
real, rendered `CalendarContract.EventsColumns`/`CalendarContract.
AttendeesColumns` API reference pages (via a real browser session, not the
`android` CLI's own offline doc-search index, which only covers guide-level
docs and returned "no document found" for the raw Javadoc reference pages
when tried first) - not assumed from the Java constant's own name, which
caught one real, easy-to-miss mismatch (`EventsColumns.STATUS`'s actual
column-name string is `"eventStatus"`, not the more obvious-looking
`"status"`).

Headless by design (no launcher icon, no MainActivity) - it's never meant to
be opened or interacted with directly, only driven via `adb shell pm grant`/
`adb shell cmd role add-role-holder`/`adb shell content query`/
`adb uninstall` from `routes/mobile.py`'s three workers, each of which
always installs it, grants exactly what's needed for that one extraction,
queries, then reverses every change and uninstalls before finishing.

## Why the built APK is committed, not downloaded

Unlike every other vendored tool this app pulls in at install time (UAC,
mquire, AVML, WinPmem), this one is **this project's own code**, not a
third-party tool - so `pif-companion.apk` is committed directly into this
directory as a small (~10 KB) prebuilt binary, and `install.py` just copies
it into `INSTALL_DIR/android_companion_tools/` at install time. This mirrors
this project's own established `scalpel.conf` precedent: a static asset that
ships with the repo needs no extra deploy logic, since it's already sitting
at its final location the moment the repo is cloned to `/opt/pi-forensics`.

Building it via Gradle/AGP on the Raspberry Pi itself at install time was
deliberately ruled out - a full Android SDK/Gradle/AGP build is a genuinely
heavy operation (100+ MB of SDK components, several minutes even on a fast
dev machine) this low-power ARM board's already-documented tight storage/CPU
budget shouldn't be asked to carry, unlike mquire's comparatively
lightweight `cargo build --release`.

## How it was built (and how to rebuild it)

Built with Google's own official `android` CLI
(https://developer.android.com/tools/agents/android-cli), not Android
Studio - confirmed live that its bundled SDK-management (`android sdk
install`) and its wrapping of a standard Gradle project work entirely
headlessly. To rebuild after a source change:

```
cd android_companion/pif_companion_src
# JAVA_HOME must point at a real JDK 17 (Gradle itself doesn't use the
# `android` CLI's own embedded JVM); ANDROID_HOME at an SDK with
# platforms/android-37.0 + build-tools/37.0.0 installed (`android sdk
# install platforms/android-37.0 build-tools/37.0.0 platform-tools`).
./gradlew assembleRelease --no-daemon
# app/build/outputs/apk/release/app-release.apk -> copy to
# android_companion/pif-companion.apk, replacing the committed copy.
```

Signed with the debug signing config (matches adbsms's own `min` module) -
appropriate for a side-loaded app this project installs itself via `adb`,
never distributed through the Play Store.

## Known, disclosed gap

Never yet run against a real Android device - no real device was connected
during any provider's build session. Every individual piece (the relay-
provider mechanism itself, mirrored from adbsms's own proven design; the
real `content://com.android.contacts/data`, `content://call_log/calls`,
`content://sms`, and `content://com.android.calendar/{events,attendees}`
URIs and their real, stable permission/role requirements, confirmed via the
`android` CLI's own official doc-search tool, adbsms's own real source for
SMS specifically, and a real live browser session against Google's own API
reference pages for Calendar's exact column/constant values) is
independently grounded, but the fully-integrated real-device happy path
(install -> grant/role-assign -> query -> parse -> uninstall/role-restore)
has never been exercised end to end for any of the four data types. Worth a
real confirmation the next time a real Android phone is available.
