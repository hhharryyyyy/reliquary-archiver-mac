# Reliquary Archiver Mac

Tiny Mac + USB iPhone fork of [IceDynamix/reliquary-archiver](https://github.com/IceDynamix/reliquary-archiver) for exporting Honkai: Star Rail inventory data to Fribbels JSON.

I technically have Windows, but I mainly use a Mac and play HSR on iPhone, and I was too lazy to set up the Windows flow. I got this working well enough to generate a valid JSON export, so I am posting the snapshot here in case it helps someone else.

I am too lazy to maintain this, so I am not accepting PRs or making updates. If you want to make changes, fork it. If you have issues getting it to work, ask Claude Code/Codex for help.

## Use It

1. Install Xcode and open it once.
2. Download the latest `reliquary-archiver-mac-*.tar.gz` from Releases.
3. Extract it and run:

```sh
sudo ./install-macos-capture-permissions.sh
```

4. Open a new terminal window.
5. Connect your iPhone over USB and trust the Mac.
6. Open HSR and stop at the "Click to Start" screen.
7. Run:

```sh
./reliquary-archiver
```

8. Tap to enter the game, wait for `archive_output-...json`, then import it into Fribbels.

## Build From Source

```sh
brew install rust
cargo build --locked --release --no-default-features --features pcap,stream
sudo ./scripts/install-macos-capture-permissions.sh
./target/release/reliquary-archiver
```

## Notes

- `Cargo.lock` is committed and builds use `--locked` so dependency versions stay pinned.
- Larger HSR updates can break protocol parsing. In your fork, try bumping the `reliquary` dependency tag, running `cargo update -p reliquary`, and rebuilding.
- If game-data download fails during build, refresh `resources/fallback/*.json` from Dimbreath's `turnbasedgamedata` repo.
