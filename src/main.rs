use std::env;

mod tty;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: sshspy PID");
        std::process::exit(1);
    }

    let pid1 = args[1].clone();
    let pid2 = args[1].clone();

    let read_handle = std::thread::spawn(move || tty::read(&pid1));
    let write_handle = std::thread::spawn(move || tty::write(&pid2));

    read_handle.join().unwrap();
    write_handle.join().unwrap();
}
