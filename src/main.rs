use clap::{Args, Parser};

mod tty;

#[derive(Parser)]
// #[command(version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    opts: Opts,

    /// Read-only mode. Unable to write anything to the target pts
    #[arg(short, long, default_value_t = false)]
    readonly: bool,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct Opts {
    /// PID of the sshd pts process you want to sshnoop on
    #[arg(long)]
    pid: Option<String>,

    /// Automatically attach to the most recently created sshd pts process
    #[arg(short, long)]
    auto: bool,

    /// List all sshd pts processes you can attach to
    #[arg(short, long)]
    list: bool,
}

fn main() {
    let cli = Cli::parse();

    let mut pts_processes = tty::get_options();

    if cli.opts.list {
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

    let pid = if cli.opts.auto {
        if let Some(p) = pts_processes.pop() {
            p.pid.to_string()
        } else {
            eprintln!("No TTY session to attach to");
            return;
        }
    } else if cli.opts.pid.is_some() {
        cli.opts.pid.unwrap()
    } else {
        eprintln!("Invalid Args");
        return;
    };

    // Default to be the most recent sshd process
    let pid_read = pid.clone();

    if cli.readonly {
        println!("Connecting in readonly mode. Any input will not be reflected on the target tty. Use CTRL+C to exit.")
    }

    let read_handle = std::thread::spawn(move || tty::read(pid_read));

    if !cli.readonly {
        // TODO: Set up a pubsub message pipeline between the threads, so that we can ensure both threads
        // close when the close command is sent i.e. CTRL+D
        let write_handle = std::thread::spawn(move || tty::write(pid));
        write_handle.join().unwrap();
        dbg!("write joined");
    }

    read_handle.join().unwrap();
    dbg!("read joined");
}
