use std::env;

mod tty;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: sshspy PID");
        std::process::exit(1);
    }

    tty::write(&args[1], true);
}

fn init(tty: &str) {
    // Start reading strace stuff

    // Open the channel to write
}
