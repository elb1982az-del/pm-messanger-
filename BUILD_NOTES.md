# P/M (Private Messenger) — Kivy + Flask relay

## Files
- `main.py` — Kivy client (login gate `OT76` / `love you`, Fernet-encrypted payloads, 30-minute local message purge loop)
- `server.py` — Flask relay (`/send`, `/get?after=N`), purges messages older than 1800 s
- `buildozer.spec` — P4A packaging config → `org.private.pm_messenger`, arm64-v8a + armeabi-v7a, INTERNET only
- `build.sh` — one-command build for x86_64 Linux
- `.github/workflows/build-apk.yml` — builds the APK in CI, no local Linux needed

## Why this host cannot run the build
This device runs an **aarch64 Android-derived kernel (4.19, GKI `ab10812814`)** with
`CONFIG_BINFMT_MISC is not set`. Buildozer/P4A downloads the Android SDK/NDK as
**x86_64 Linux binaries** (aapt2, NDK clang…). Without x86 binfmt emulation they cannot
execute on this machine, so `buildozer android debug` is impossible *here* — run it on any
x86_64 Linux box, or let GitHub Actions do it (`.github/workflows/build-apk.yml`).

## Fixes applied vs. the original transcript
1. `sm.add_screen(...)` → `sm.add_widget(...)` — `ScreenManager` has no `add_screen`; original crashed at launch.
2. Removed `self.scroll.add_widget(self.scroll)` — widget cannot be its own parent; original crashed opening the chat screen. (The two "fixed reference container" lines below it already handled this.)
3. Polling dedup — server now additionally returns `last_index` and the client pulls `after=last_index`, so each poll no longer re-delivers (and re-decrypts/duplicates) the same 10 messages every cycle.
4. Server now enforces the same 1800 s purge using the `server_ts` it stamps (was stored but never used).

## Runtime wiring
- Local test: `python3 server.py`, then start the app (set `SERVER_URL` to the phone's-reachable address, e.g. a LAN/relay IP instead of `127.0.0.1`).
- Deployment: change `SERVER_URL` in `main.py` to your public relay IP.
