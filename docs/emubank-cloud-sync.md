# EmuBank cloud saves

This fork embeds the EmuBank device-sync companion in Dolphin's shared UI layer, so the same sync
engine is used by the Qt desktop app, Android app, and NoGUI frontend.

Deploy it with the companion changes in `../emu-bank`. They provide secure native-device pairing
and reactivate conflicted device bindings when an EmuBank revision is selected. Run EmuBank's
database migrations as part of deployment.

## Set up a device

1. On desktop, open **Settings > EmuBank**. On Android, open
   **Settings > Config > EmuBank**.
2. Enter the EmuBank base URL, select **Connect EmuBank Account**, and approve the named Dolphin
   installation in the system browser. Dolphin generates the persistent device secret locally;
   EmuBank receives only its SHA-256 hash, and neither the secret nor your account password is put
   in the browser link. HTTPS is required unless insecure HTTP is explicitly enabled for a trusted
   development network.
3. In EmuBank's **Devices & Sync** page, connect each cloud save to its logical Dolphin path.
   Supported bindings are files below `GC/` or `Wii/`, such as
   `GC/USA/Card A/01-GC6E-pokemon_colosseum.gci`. The portion after `Wii/` is relative to Dolphin's
   configured NAND root, including a custom root outside the user directory; the portion after
   `GC/` is relative to Dolphin's GameCube user-data root. EmuBank enforces each binding's
   `download_only`, `upload_only`, or `two_way` direction on the API as well as Dolphin honoring it
   locally.
4. Use **Sync Now**, or let automatic synchronization run. A masked manual device-token field
   remains available as an advanced fallback for older or independently deployed servers.

For GameCube games, GCI Folder memory-card mode is strongly recommended. A per-game `.gci` file is
smaller and safer to synchronize than a whole raw memory card. Raw `.raw` files are supported, but
Dolphin never replaces any bound file while emulation is active.

## Sync and conflict behavior

- Dolphin verifies every downloaded body against the revision ID and SHA-256 response headers,
  rather than trusting a possibly stale manifest, and replaces the local file through a temporary
  file only while emulation is stopped.
- Before a game launches, Dolphin performs a blocking pull so the emulated memory card opens the
  selected cloud revision. A complete sync pass has a 30-second budget; an unreachable server does
  not prevent the game from launching after that budget.
- While playing, Dolphin wakes the sync worker after a successful GCI/raw memory-card flush or a
  dirty Wii title-data file close. Events are coalesced, and a changed file uploads only after the
  same complete hash is observed across multiple checks. Periodic polling remains a recovery path;
  remote changes remain pending until emulation stops. Raw cards inherit Dolphin's normal flush
  cadence (up to about 15 seconds); GCI Folder mode provides finer-grained updates.
- Automatic checks run while the Dolphin process is alive. Android may stop an idle process; the
  pre-launch sync catches up the next time Dolphin starts a game.
- Android performs a bounded final sync after Core shutdown, when all save files have closed, and
  before finishing the emulation activity. A force-stop or abrupt OS process kill cannot guarantee
  network completion, so the next startup still reconciles any local change.
- Each successful sync records the common revision in `Config/EmuBankSyncState.json`. If local and
  cloud copies both change from that revision, the upload uses the old base hash. EmuBank retains
  it as a conflict revision instead of replacing the active cloud save.
- Loading any savestate invalidates the recorded common ancestor before another upload. The first
  differing host save after the load is therefore retained as a conflict instead of letting older
  savestate memory-card bytes overwrite newer cloud progress.
- If a local file and an existing cloud revision differ on the first sync and no common revision
  can be proven, Dolphin also creates an EmuBank conflict. Resolve it in EmuBank; Dolphin then
  follows the selected revision.

This first integration synchronizes file contents, not local file deletion. Removing a bound file
locally does not delete its cloud revision.

Wii title saves are often multi-file directories. Individual supported files can be bound and
backed up, but this first integration does not yet create an atomic whole-title `data.bin` snapshot
while a Wii game is running. Whole-save packaging should happen after exit in a future extension.

The resulting device token is stored in Dolphin's configuration. Protect the Dolphin user
directory and revoke the device in EmuBank if the token is exposed.

## Configuration keys

The desktop and Android settings UIs write these keys to the `[EmuBank]` section of `Dolphin.ini`:

```ini
[EmuBank]
Enabled = True
ServerURL = https://bank.example.com
DeviceToken = device-id.secret
AllowInsecureHTTP = False
LiveSync = True
SyncIntervalSeconds = 5
```
