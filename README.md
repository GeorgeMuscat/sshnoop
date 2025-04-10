sshnoop is designed to be a standalone binary (strace dependency to be removed shortly) that is used on linux endpoints to read and write to ongoing incoming SSH connections.

The current features allow the user to specify a target sshd session using pid or pts, list all valid target sshd sessions or automatically connect to the most recent connection.

By default sshnoop is started in write mode, however read-only mode can be used.

Our current testing has been done with root level access.

The program doesn't allow for you to sshnoop on its parent sshd instance (if it exists).

## Usage Requirements

-   The program must be run with the `CAP_SYS_ADMIN` capability.
-   `strace`

## How to use

Either download the release from [Releases](https://github.com/GeorgeMuscat/sshnoop/releases) or build it using the instructions outlined in **Building**.

```
Usage: sshnoop [OPTIONS] <--pid <PID>|--pts <PTS>|--auto|--list>

Options:
      --pid <PID>  PID of the sshd pts process you want to sshnoop on
      --pts <PTS>  PTS number of the target sshd pts process you want to sshnoop on
  -a, --auto       Automatically attach to the most recently created sshd pts process
  -l, --list       List all sshd pts processes you can attach to
  -r, --readonly   Read-only mode. Unable to write anything to the target pts
  -h, --help       Print help
```

## Building

For debugging:

```
cargo build
```

For release:

```
cargo build --release
```

For GNU/Linux release:

```
cargo build --release --target x86_64-unknown-linux-gnu
```

Using [`cross`](https://github.com/cross-rs/cross) for GNU/Linux release:

```
cross build --release --target x86_64-unknown-linux-gnu
```
