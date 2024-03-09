use std::env;

mod tty;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: sshspy PID");
        std::process::exit(1);
    }
    tty::read(&args[1]);
}
