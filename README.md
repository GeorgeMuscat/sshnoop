A rewrite of [SSHPry](https://github.com/nopernik/SSHPry) in Rust.

## Requires

-   `strace`
-   `root`

## How to use

```
Usage: sshnoop <--pid <PID>|--auto|--list>

Options:
  -p, --pid <PID>  PID of the sshd pts process you want to sshnoop on
  -a, --auto       Automatically attach to the most recently created sshd pts process
  -l, --list       List all sshd pts processes you can attach to
  -h, --help       Print help
```
