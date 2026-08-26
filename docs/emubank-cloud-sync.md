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
3. When a GameCube game starts, Dolphin sends its trusted disc metadata (game ID, title, region,
   and revision, but never ROM bytes) to EmuBank. EmuBank first matches an owned save and creates
   the device binding automatically. If the game is not in the library, an approved device can
   create a private game, playthrough, and save entry; the first GCI write supplies the exact save
   filename. Ambiguous matches remain untouched and require a choice in EmuBank. The manual
   **Devices & Sync** binding UI remains available for raw memory cards, Wii multi-file saves, and
   other advanced cases.
4. Automatic bindings are files below `GC/` or `Wii/`, such as
   `GC/USA/Card A/01-GC6E-pokemon_colosseum.gci`. The portion after `Wii/` is relative to Dolphin's
   configured NAND root, including a custom root outside the user directory; the portion after
   `GC/` is relative to Dolphin's GameCube user-data root. EmuBank enforces each binding's
   `download_only`, `upload_only`, or `two_way` direction on the API as well as Dolphin honoring it
   locally. Binding components use the portable Windows filename rules on every platform. A
   manifest is rejected if two paths could be Unicode case/normalization aliases on any supported
   save volume, or if one file target would be the parent of another; a single international
   filename remains supported.
5. Use **Sync Now**, or let automatic synchronization run. Dolphin shows the current phase and
   final result in the EmuBank settings page, in Android's launch progress overlay, and through its
   normal in-game on-screen messages. A masked manual device-token field
   remains available as an advanced fallback for older or independently deployed servers.

For GameCube games, GCI Folder memory-card mode is strongly recommended. A per-game `.gci` file is
smaller and safer to synchronize than a whole raw memory card. Raw `.raw` files are supported, but
Dolphin never replaces any bound file while emulation is active.

## Sync and conflict behavior

- Dolphin verifies every downloaded body against the exact manifest revision ID, size, and SHA-256
  response headers. It also rechecks that the local file did not change during the request before
  replacing it through an atomic exchange/no-overwrite operation where supported, or a prearmed
  recovery transaction on older Android storage. It keeps a content-addressed backup of every
  divergent local file and only downloads while emulation is stopped. A concurrent writer's inode
  is retained instead of being destroyed by the cloud install.
- Before a game launches, Dolphin performs a blocking reconciliation. A recorded common hash is
  authoritative: if only the cloud changed, that revision is restored; if only the local file
  changed, it is uploaded. When no common hash can decide the winner, a local write clearly newer
  than the cloud revision promotes the local save directly in EmuBank. A later cloud upload time
  alone is not trusted because somebody can upload older game progress later. Ambiguous ordering
  creates a conflict and keeps the local bytes in place. A cloud pointer can refer to a reactivated
  historical revision, so neither pointer movement nor ordinary server-directed restore advice may
  override a clearly newer local file. Resolver advice is accepted only for the exact binding,
  revision, and reported local hash that the active-game resolver checked, and ordinary advice can
  replace divergent local bytes only when the durable common base independently proves that the
  local copy stayed unchanged while the cloud changed. An unresolved 409 conflict, unknown
  ancestry, or savestate invalidation cannot turn resolver advice into permission to overwrite
  local bytes. Download-only mode and an authenticated explicit server revision selection remain
  cloud-authoritative. Dolphin records that exact selected revision locally before requesting its
  body and binds the authorization to the exact local hash (or absence) it may replace. It retains
  that authorization until installation succeeds because the server's download response consumes
  its one-shot pending marker; a crash or later local edit cannot transfer it to different bytes.
  If those expected local bytes change, Dolphin durably tombstones that exact pending selection;
  the same still-pending server choice cannot silently bind itself to a later local save.
- Pre-launch network requests share a 12-second deadline; stopped/final sync passes use a
  30-second deadline. An unreachable server does not prevent the game from launching after the
  shorter pre-launch deadline. A local save install that was already committing is allowed to
  finish before launch so Core cannot open a half-replaced file. If exceptional filesystem I/O
  cannot yield within that boundary, Dolphin cancels this boot attempt, lets the serialized helper
  finish without Core touching the namespace, and asks the user to retry. The gate runs before Core
  initializes the emulated system or graphics backend, so it cannot stall a half-initialized
  renderer. Android shows the phase in its launch overlay; desktop keeps processing paint and
  timer events while it waits. If an exceptional filesystem recovery cannot return the retained
  inode to the canonical save path, Dolphin records a credential-independent recovery quarantine
  in both its sync state and `Config/EmuBankRecovery.json` and cancels every launch until the exact
  retained body is restored at the exact canonical path and save root armed by the transaction.
  Recovery/state/backup namespace commits are accepted only after both their file data and their
  namespace publication complete through the platform durability primitive (directory `fsync` on
  POSIX, `F_FULLFSYNC` file flushes on Apple systems, and write-through moves on Windows). An
  existing Windows path restored outside Dolphin is republished with write-through renames before
  its quarantine can clear. A sync-lock timeout, disabled/offline server, restart, root switch, or
  temporarily unavailable custom save root cannot bypass that quarantine. Android storage that
  rejects atomic exchange uses a lock-guarded, hash-bound recovery transaction; other filesystems
  without a safe existing-file replacement primitive refuse the replacement and leave the local
  file in place. Recovery is a global barrier: no other binding enters ordinary upload/download
  policy until every armed canonical path is repaired. A transaction which began with no local
  file may roll forward to the server's newer authenticated current revision after a crash. A
  transaction which displaced local bytes remains rollback-bound to its exact required hash until
  every displaced or concurrent inode is durably retained; it then becomes an authenticated cloud
  roll-forward transaction. If a failed
  missing-file publication leaves readable bytes that differ from the required cloud revision,
  Dolphin durably backs them up and keeps the quarantine armed: the bytes may be either a real
  concurrent local save or a short-write fragment, so they are never fed into normal upload
  policy. Review the content-addressed backup and move the canonical file aside to let recovery
  reinstall the authenticated cloud body. If the retained file is a genuine local save, it can be
  restored after recovery clears and reconciled in a new sync pass.
- One Dolphin process owns `EmuBankSync.lock` in `Config`, every resolved GC/Wii save root, and
  every prior root named by an armed recovery record for as long as it can access those
  namespaces. Another process using either the same user folder or the same external save root
  cannot launch or load a savestate until that owner exits. This prevents independently cached
  sync state—or an already-open save descriptor—from racing a cloud install across profiles.
  Dolphin pins the filesystem identity of every locked directory and of
  each configured path leading to it, and refuses further reconciliation if one is swapped while
  running. The durable-state cache is also pinned to the Config directory which supplied it;
  recovery generations cannot roll back, and a stale pre-lock cache is refreshed only while that
  same Config namespace is independently locked. Windows binds full 128-bit file IDs to the mounted
  volume GUID (or the normalized final network path), rejects unsupported/sentinel IDs, and fails
  closed when a root cannot prove that combined identity. This distinguishes simultaneously
  mounted filesystem clones as well as ReFS identities; legacy IDs are not accepted. Changing to a
  different Wii root after the first lock acquisition is also restart-only, so two profiles cannot
  retain crossed root-lock sets; restart Dolphin after changing, moving, or replacing a user or
  save-root directory.
  Concurrent profiles must configure save roots as either disjoint directories or the same
  resolved directory. A single manifest is rejected when two binding paths may identify the same
  file. Nested roots, distinct bind/reparse views which converge below the root, and hard-linked
  save endpoints across otherwise distinct roots are unsupported; close the other Dolphin process
  before using such a layout. Root-local advisory locks cannot prove those
  cross-profile aliases, while globally serializing every unrelated Dolphin profile would make
  legitimate multi-instance setups unusable.
- While playing, Dolphin wakes the sync worker after a successful GCI/raw memory-card flush or a
  dirty Wii title-data file close. Events are coalesced behind a two-second quiet period, and the
  file is accepted only if its size and modification time remain stable throughout the read.
  Dolphin does not periodically fetch and hash every binding during play; event-driven retries and
  the final stopped pass provide catch-up.
  The configured interval is a minimum delay between all automatic attempts, including failed live
  retries, savestate notifications, and configuration changes, so a 180-second setting cannot
  collapse into a tight retry loop. Manual Sync Now, a newly authorized connection, pre-launch
  checks, and final shutdown syncs may bypass that delay. Remote changes remain pending until
  emulation stops. Raw cards inherit Dolphin's normal flush cadence (up to about 15 seconds); GCI
  Folder mode provides finer-grained updates.
- Automatic checks run while the Dolphin process is alive. Android may stop an idle process; the
  pre-launch sync catches up the next time Dolphin starts a game.
- Android performs a bounded final sync after Core shutdown, when all save files have closed, and
  before finishing the emulation activity. A force-stop or abrupt OS process kill cannot guarantee
  network completion, so the next startup still reconciles any local change.
- Each successful sync records the common revision in `Config/EmuBankSyncState.json`. If both
  copies later change, a provably later local write can be promoted directly. A later cloud upload
  timestamp alone or ambiguous ordering uses the old base hash so EmuBank retains a conflict
  without replacing either local bytes or the active cloud revision. State and recovery metadata
  have fixed file-size and record-count limits; unreadable, unsupported, or oversized safety state
  blocks reconciliation and launch rather than being silently discarded.
- Every attempted savestate load creates and flushes a unique invalidation marker before
  deserialization begins, while holding the same save-namespace gate used by sync. If that marker
  or gate cannot be acquired, Dolphin refuses the load before it can mutate a memory card. Failed
  or truncated loads remain conservatively marked because they may already have restored part of
  a save device. Before deserialization, Dolphin also taints every known binding and durably records
  the affected title plus configured/discovered save paths. A root-level epoch remains set through
  the running session and, after a crash, until a complete stopped manifest is durably tainted and
  all markers are consumed. A binding omitted from that manifest keeps its safety state; unmatched
  title/path selectors remain as targeted taints without repeatedly invalidating unrelated saves.
  The first differing host save after the load is therefore retained as a conflict instead of
  letting older savestate memory-card bytes overwrite newer cloud progress.
- If a local file and existing cloud revision differ on the first sync and neither is clearly
  newer, Dolphin creates an EmuBank conflict but continues to use the local copy. Resolve it in
  EmuBank; Dolphin follows the selected revision only after that explicit resolution.

This first integration synchronizes file contents, not local file deletion. Removing a bound file
locally does not delete its cloud revision.

If one GameCube title owns multiple independent local GCI entries, Dolphin leaves new automatic
links untouched until each entry can be selected in **Devices & Sync**. Existing explicit bindings
still synchronize. This avoids collapsing separate in-game save entries into one cloud revision.

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
SyncIntervalSeconds = 30
```
