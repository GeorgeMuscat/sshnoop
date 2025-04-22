use nix::{
    libc::ENOSYS, sys::{
        ptrace::{self, Options},
        signal::Signal,
        wait::{waitpid, WaitStatus},
    }, unistd::Pid
};
use std::{
    error::Error,
    ffi::{c_long, c_void},
    os::fd,
    sync::mpsc::Sender,
};

use thiserror::Error;

// lots of help and info here: https://medium.com/@ohchase/using-rust-and-ptrace-to-invoke-syscalls-262dc585fcd3

#[derive(Error, Debug)]
pub enum HostError {
    #[error("Process not found `{0}`")]
    ProcessNotFound(String),
    #[error("Nix Error `{0}`")]
    NixError(#[from] nix::errno::Errno),
    #[error("Unexpected Wait Status `{0:#?}`")]
    UnexpectedWaitStatus(WaitStatus),
}

type HostResult<T> = Result<T, HostError>;

struct TargetProcess {
    pid: Pid,
}

// struct TargetProcess<'a, O> {
//     // Exists so we can add further context if required.
//     // Also allows us to be smart about detaching from the target process.
//     pid: Pid,
//     // Want to define a type of function that accepts the args required to hook a specific syscall with specific conditions. e.g. read syscall when fd is 10.
//     // This could be a pair of functions. The first being the predicate that must be satisfied and the second being the function to execute if the predicate returns true.
//     // TODO: Figure out traits/signatures that make sense to ensure this is what will happen
//     hooks: Vec<Hook<'a, O>>,
// }

// struct Hook<'a, O> {
//     predicate: &'a dyn Fn(&user_regs_struct) -> bool,
//     execute: &'a dyn Fn(&user_regs_struct) -> Option<O>,
// }

impl TargetProcess {
    /// Only method to create a TargetProcess
    fn attach(pid: Pid) -> HostResult<Self> {
        ptrace::attach(pid)?;
        Ok(Self { pid })
    }

    fn read(&self, addr: *mut c_void) -> HostResult<c_long> {
        ptrace::read(self.pid, addr).map_err(HostError::NixError)
    }
}

impl Drop for TargetProcess {
    fn drop(&mut self) {
        // tell the OS to try to detach from the target. If it fails, oh well /shrug.
        let _ = ptrace::detach(self.pid, None);
    }
}

// TODO: Define Message properly
struct Message {}

// Create function to be run in a thread that takes a Sender side of a mpsc. This function will create a TargetProcess, and start checking all read syscalls with arg0 (ebx) being == fd. It will then read all the bytes being written and send them in a message over the channel.
fn read_sshd_out(pid: Pid, fd: u64, tx: Sender<Message>) -> HostResult<()> {
    // Only care about syscalls, specifically read.
    ptrace::seize(pid, Options::PTRACE_O_TRACESYSGOOD)?;

    // Loop getting the regs of each stop

    loop {
        // when target process makes a syscall, it will enter the stopped state. We must wait for this
        match waitpid(pid, None).map_err(HostError::NixError)? {
            WaitStatus::PtraceSyscall(_) => {
                // Only want to match PtraceSyscall, which maps to the process being stopped when making a syscall when PTRACE_O_TRACESYSGOOD is set.
                // We don't care about the case where it is continuing after the syscall has been completed.
                let regs = ptrace::getregs(pid)?;

                // We care about READ syscall with desired fd as arg0. the regs will be
                // rax == 0
                // rdi == fd
                // rsi == pointer to the start of the buf being read into
                // rdx == length of the buffer being read into
                // https://x64.syscall.sh
                // I think we actually need orig_rax, as rax is some other value when things get stopped TODO: confirm this.
                // Mentioned here: https://zbysiu.dev/blog/implementing-simple-strace/
                if !(regs.orig_rax == 0 && regs.rdi == fd && regs.rax == -ENOSYS) {
                    continue;
                }


                regs.rax == ENOSYS

                todo!("Check that the syscall does/doesn't match our conditions. If it does, send a message over the channel.");
            }
            _ => continue,
        }

        break;
    }
    Ok(())
}
