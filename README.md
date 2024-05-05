sshnoop is designed to be a standalone binary that is used on linux endpoints to read and write to ongoing incoming SSH connections.

The current features allow the user to specify a specific sshd pid, list all valid sshd sessions or automatically connect to the most recent connection.

Our current testing has been done with root level access.

The program doesn't allow for you to sshnoop on its parent sshd instance (if it exists).

## Usage Requirements

-   `strace`

## How to use

Either download the release from [Releases](https://github.com/GeorgeMuscat/sshnoop/releases) or build it using the instructions outlined in **Building**.

```
Usage: sshnoop <--pid <PID>|--auto|--list>

Options:
  -p, --pid <PID>  PID of the sshd pts process you want to sshnoop on
  -a, --auto       Automatically attach to the most recently created sshd pts process
  -l, --list       List all sshd pts processes you can attach to
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
