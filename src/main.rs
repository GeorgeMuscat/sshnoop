use clap::{ArgGroup, Parser};

mod tty;

#[derive(Parser)]
// #[command(version, about, long_about = None)]
#[clap(group(
    ArgGroup::new("opts")
        .required(true)
        .args(&["pid", "auto", "list"]),
))]
struct Args {
    /// PID of the sshd pts process you want to sshnoop on
    #[arg(short, long)]
    pid: Option<String>,

    /// Automatically attach to the most recently created sshd pts process
    #[arg(short, long)]
    auto: bool,

    /// List all sshd pts processes you can attach to
    #[arg(short, long)]
    list: bool,
}

fn main() {
    let args = Args::parse();

    let mut pts_processes = tty::get_options();

    if args.list {
        pts_processes.iter().for_each(|p| {
            println!(
                "PID: {} TTY: {} USER: {}",
                p.pid,
                tty::tty_of_sshd(&p.pid.to_string()).expect("Failed to get TTY"),
                &tty::get_pts_user(&p.pid.to_string()).expect("Failed to get user")
            )
        });
        return;
    }

    let pid: String;

    if args.auto {
        pid = if let Some(p) = pts_processes.pop() {
            p.pid.to_string()
        } else {
            eprintln!("No TTY session to attach to");
            return;
        };
    } else if args.pid.is_some() {
        pid = args.pid.unwrap();
    } else {
        return;
    }

    // Default to be the most recent sshd process
    let pid1 = pid.clone();
    let pid2 = pid.clone();

    let read_handle = std::thread::spawn(move || tty::read(&pid1));
    let write_handle = std::thread::spawn(move || tty::write(&pid2));

    read_handle.join().unwrap();
    write_handle.join().unwrap();
}
