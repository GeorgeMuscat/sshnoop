use std::net::SocketAddr;

use clap::{Args, Parser};
use tabled::{settings::Style, Table, Tabled};

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

    /// PTS number of the target sshd pts process you want to sshnoop on
    #[arg(long)]
    pts: Option<String>,

    /// Automatically attach to the most recently created sshd pts process
    #[arg(short, long)]
    auto: bool,

    /// List all sshd pts processes you can attach to
    #[arg(short, long)]
    list: bool,
}

#[derive(Tabled)]
struct ListOptions {
    #[tabled(rename = "PID")]
    pid: i32,
    #[tabled(rename = "PTS")]
    pts: String,
    #[tabled(rename = "USER")]
    user: String,
    #[tabled(rename = "REMOTE_ADDRESS")]
    remote_address: SocketAddr,
}

fn main() {
    let cli = Cli::parse();

    let mut pts_processes = tty::get_options();

    if cli.opts.list {
        let options = pts_processes.iter().map(|p| ListOptions {
            pid: p.pid,
            pts: tty::pts_of_sshd(&p.pid.to_string())
                .unwrap_or_else(|_| panic!("Failed to get pts for pid: {}", p.pid)),
            user: tty::get_pts_user(&p.pid.to_string())
                .unwrap_or_else(|_| panic!("Failed to get user for pid: {}", p.pid)),
            remote_address: tty::pid_to_socket_address(p.pid)
                .unwrap_or_else(|| panic!("Failed to get remote address for pid: {}", p.pid)),
        });

        let mut table = Table::new(options);
        table.with(Style::psql());
        println!("{}", table);
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
        // Check that pid is in the options provided
        let Ok(pid) = cli.opts.pid.unwrap().parse() else {
            eprintln!("Unable to parse pid.");
            return;
        };

        if pts_processes.iter().any(|p| p.pid == pid) {
            pid.to_string()
        } else {
            eprintln!("pid is not a possible target.");
            return;
        }
    } else if cli.opts.pts.is_some() {
        // TODO: Translate pts to pid for other funcs. This could mean getting all options and picking one
        if let Some(p) = tty::pts_to_pid(&cli.opts.pts.expect("Checked that value is Some")) {
            p.to_string()
        } else {
            eprintln!("Invalid pts provided");
            return;
        }
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
        println!("disconnected writer");
        println!("to disconnect reader, press ctrl+c");
    }
    read_handle.join().unwrap();
}
