A rewrite of [SSHPry](https://github.com/nopernik/SSHPry) in Rust.

sshnoop is designed to be used on linux endpoints/servers to read and write to ongoing SSH connections to that machine.

Our current testing has been done with root level access.

## Usage Requirements

-   `strace`

## How to use

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
cargo build --release --target x86_64-unknown-linux-gnu
```
