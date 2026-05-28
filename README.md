# Reliquary Archiver Mac

Mac-only CLI for exporting Honkai: Star Rail relic, light cone, character, and material data from an iPhone into the Fribbels optimizer format.

This is a small fork of [IceDynamix/reliquary-archiver](https://github.com/IceDynamix/reliquary-archiver). It keeps the upstream parser/export pipeline and focuses on one flow: macOS + USB iPhone.

## Status

- This is a public snapshot, not an actively maintained project.
- Android, Windows, router capture, and GUI flows are out of scope here.
- Please fork the repo if you want changes. Do not send PRs expecting maintenance.

## Quick Start

Install Xcode and open it once.

Download the latest `reliquary-archiver-mac-*.tar.gz` from Releases, extract it, then run the one-time permission setup:

```sh
sudo ./install-macos-capture-permissions.sh
```

Open a new terminal window after setup, then run live capture from a USB-connected iPhone:

```sh
./reliquary-archiver
```

To build from source instead, install Rust if needed:

```sh
brew install rust
```

```sh
cargo build --locked --release --no-default-features --features pcap,stream
```

Then run:

```sh
sudo ./scripts/install-macos-capture-permissions.sh
```

Open a new terminal window after setup, then run:

```sh
./target/release/reliquary-archiver
```

## Capture Flow

1. Connect the iPhone over USB and tap "Trust This Computer".
2. Launch HSR and stop at the "Click to Start" screen.
3. Run the archiver.
4. Tap to enter the game.
5. Wait for `archive_output-...json`.
6. Import the JSON into Fribbels Star Rail Optimizer.

If more than one iPhone is connected, pass a UDID:

```sh
./reliquary-archiver --udid <UDID>
```

To import an existing packet capture instead of live iPhone traffic:

```sh
./reliquary-archiver --pcap capture.pcapng
```

The CLI creates Apple's Remote Virtual Interface (`rvi`), captures only that interface, and cleans it up when the process exits.

## If It Breaks After An HSR Update

Small game updates often keep working. Larger updates can change the packet protocol or game data.

Try this in your fork:

1. Update the `reliquary` dependency tag in `Cargo.toml`.
2. Run `cargo update -p reliquary`.
3. Rebuild with `cargo build --locked --release --no-default-features --features pcap,stream`.
4. If the build script cannot fetch game data, refresh `resources/fallback/*.json` from Dimbreath's `turnbasedgamedata` repo.

`Cargo.lock` is committed and builds use `--locked` so dependency versions stay pinned unless you intentionally update them.

## Development Notes

The parser is provided by the upstream `reliquary` crate. The Mac work should stay focused on:

- pcap device discovery and selection
- capture permission/error messages
- reproducible iPhone RVI capture instructions
- macOS CI and release packaging

Avoid rewriting the protocol parser unless upstream stops being usable.
