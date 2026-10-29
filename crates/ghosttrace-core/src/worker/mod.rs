//! Isolated parser worker: resolution, spawn restrictions, and frame I/O
//! (plan P8.2).
//!
//! The worker is the packaged CLI binary in a private mode. The parent never
//! searches `PATH` or the evidence directory: it resolves the sibling binary
//! next to its own executable (or an explicit path), clears the environment,
//! runs the child in a private scratch directory, and checks the protocol and
//! build version in a handshake before sending a job.
//!
//! Restrictions are applied where the platform has them (Linux `setrlimit`,
//! `no_new_privs`, a new session); elsewhere the limitation is documented in
//! `docs/worker-protocol.md` instead of being claimed.

pub mod protocol;

use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::error::{CoreError, CoreResult};

use protocol::{
    MAX_BATCH_FRAME, MAX_CONTROL_FRAME, PROTOCOL_VERSION, Request, Response, read_frame,
    write_frame,
};

/// A resolved worker binary. Resolution is explicit: the caller passes either
/// its own executable directory's sibling or an operator-supplied path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerBinary {
    path: PathBuf,
}

impl WorkerBinary {
    /// The worker that ships beside `exe` (the desktop or CLI binary). A missing
    /// sibling is an error, never a fallback to `PATH`.
    pub fn resolve_beside(exe: &Path) -> CoreResult<Self> {
        let directory = exe.parent().ok_or_else(|| {
            CoreError::InvalidInput("the application path has no parent directory".to_string())
        })?;
        let name = if cfg!(windows) {
            "ghosttrace.exe"
        } else {
            "ghosttrace"
        };
        let path = directory.join(name);
        if !path.is_file() {
            return Err(CoreError::InvalidInput(format!(
                "the parser worker is missing beside the application (expected {}); reinstall or rebuild the pair",
                path.display()
            )));
        }
        Ok(Self { path })
    }

    /// An explicit worker path from the operator. It must name a regular file;
    /// a directory or a missing path is rejected before any spawn.
    pub fn explicit(path: impl Into<PathBuf>) -> CoreResult<Self> {
        let path = path.into();
        if !path.is_file() {
            return Err(CoreError::InvalidInput(format!(
                "the parser worker is not a regular file: {}",
                path.display()
            )));
        }
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// A spawned worker with a bounded frame reader on a helper thread. Reads use a
/// deadline so a hung or silent worker is killed instead of blocking the caller.
pub(crate) struct WorkerProcess {
    child: Child,
    stdin: ChildStdin,
    frames: Receiver<Result<Vec<u8>, String>>,
    reader: Option<JoinHandle<()>>,
    job_id: String,
}

impl WorkerProcess {
    /// Spawn the worker for `job_id`, stage the input path, and complete the
    /// handshake. `input` must already be a private staged copy.
    pub(crate) fn spawn(
        worker: &WorkerBinary,
        scratch: &Path,
        job_id: &str,
        handshake_timeout: Duration,
    ) -> CoreResult<Self> {
        let mut command = Command::new(&worker.path);
        command
            .arg("worker")
            .arg("--protocol")
            .arg(PROTOCOL_VERSION.to_string())
            .current_dir(scratch)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(unix)]
        apply_unix_restrictions(&mut command);

        let mut child = command.spawn().map_err(|error| {
            CoreError::Storage(format!("the parser worker could not be started: {error}"))
        })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| CoreError::Storage("the parser worker has no input pipe".to_string()))?;
        let stdout = child.stdout.take().ok_or_else(|| {
            CoreError::Storage("the parser worker has no output pipe".to_string())
        })?;
        let (sender, frames) = channel();
        let reader = std::thread::spawn(move || {
            let mut stdout = BufReader::new(stdout);
            loop {
                match read_frame(&mut stdout, MAX_BATCH_FRAME) {
                    Ok(Some(body)) => {
                        if sender.send(Ok(body)).is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        let _ = sender.send(Err(error.to_string()));
                        break;
                    }
                }
            }
        });
        let mut process = Self {
            child,
            stdin,
            frames,
            reader: Some(reader),
            job_id: job_id.to_string(),
        };
        process.send(&Request::Hello {
            protocol: PROTOCOL_VERSION,
            version: protocol::BUILD_VERSION.to_string(),
        })?;
        match process.recv(handshake_timeout)? {
            Some(body) => {
                let response: Response = serde_json::from_slice(&body).map_err(|error| {
                    CoreError::Storage(format!("the parser worker handshake is not valid: {error}"))
                })?;
                match response {
                    Response::Ready {
                        protocol: version,
                        version: build,
                    } if version == PROTOCOL_VERSION && build == protocol::BUILD_VERSION => {}
                    Response::Ready {
                        protocol: version,
                        version: build,
                    } => {
                        return Err(CoreError::Unsupported(format!(
                            "the parser worker speaks protocol {version} build {build}; this build needs protocol {PROTOCOL_VERSION} build {}",
                            protocol::BUILD_VERSION
                        )));
                    }
                    Response::Failed { code, message, .. } => {
                        return Err(CoreError::Unsupported(format!(
                            "the parser worker refused the handshake ({code}): {message}"
                        )));
                    }
                    _ => {
                        return Err(CoreError::Storage(
                            "the parser worker did not answer the handshake".to_string(),
                        ));
                    }
                }
            }
            None => {
                return Err(CoreError::Storage(
                    "the parser worker exited before the handshake".to_string(),
                ));
            }
        }
        Ok(process)
    }

    /// Send the real parse request after the handshake (the staged path and
    /// limits are only known then).
    pub(crate) fn send_parse(
        &mut self,
        format: &str,
        input: &Path,
        max_records: u64,
        max_record_bytes: u64,
    ) -> CoreResult<()> {
        self.send(&Request::Parse {
            job_id: self.job_id.clone(),
            format: format.to_string(),
            path: input.display().to_string(),
            max_records,
            max_record_bytes,
        })
    }

    fn send(&mut self, request: &Request) -> CoreResult<()> {
        let body = serde_json::to_vec(request)
            .map_err(|error| CoreError::Storage(format!("worker request json: {error}")))?;
        write_frame(&mut self.stdin, &body, MAX_CONTROL_FRAME)
            .map_err(|error| CoreError::Storage(format!("the parser worker pipe closed: {error}")))
    }

    /// Next frame body, `None` on a clean EOF, or an error when the deadline
    /// passes or the worker's output is unreadable.
    pub(crate) fn recv(&mut self, timeout: Duration) -> CoreResult<Option<Vec<u8>>> {
        match self.frames.recv_timeout(timeout) {
            Ok(Ok(body)) => Ok(Some(body)),
            Ok(Err(message)) => Err(CoreError::Storage(format!(
                "the parser worker produced an invalid frame: {message}"
            ))),
            Err(RecvTimeoutError::Timeout) => Err(CoreError::ResourceLimit),
            Err(RecvTimeoutError::Disconnected) => Ok(None),
        }
    }

    /// Kill the worker and reap it. Safe to call more than once.
    pub(crate) fn kill(&mut self) {
        #[cfg(unix)]
        {
            // The child is a session leader (setsid), so a process-group kill
            // also reaches anything it managed to spawn.
            let pid = nix::unistd::Pid::from_raw(self.child.id() as i32);
            let _ = nix::sys::signal::killpg(pid, nix::sys::signal::Signal::SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        self.kill();
    }
}

/// The worker's own watchdog: a job budget measured from the last progress.
pub(crate) struct Deadline {
    started: Instant,
    last_progress: Instant,
    no_progress: Duration,
    total: Duration,
}

impl Deadline {
    pub(crate) fn new(no_progress: Duration, total: Duration) -> Self {
        let now = Instant::now();
        Self {
            started: now,
            last_progress: now,
            no_progress,
            total,
        }
    }

    pub(crate) fn progress(&mut self) {
        self.last_progress = Instant::now();
    }

    /// Remaining time before either budget expires.
    pub(crate) fn remaining(&self) -> Option<Duration> {
        let now = Instant::now();
        let idle = self
            .no_progress
            .checked_sub(now.duration_since(self.last_progress))?;
        let total = self.total.checked_sub(now.duration_since(self.started))?;
        Some(idle.min(total))
    }
}

#[cfg(unix)]
fn apply_unix_restrictions(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    // Limits are deliberately generous for a legitimate large log while still
    // bounding a runaway parser. The parent also enforces a no-progress
    // deadline, so a limit is the backstop, not the primary control.
    let address_space = 1 << 30; // 1 GiB
    let cpu_seconds = 600; // 10 minutes of CPU
    let file_size = 1 << 30; // 1 GiB written (the worker should write nothing)
    let open_files = 128;
    unsafe {
        command.pre_exec(move || {
            nix::unistd::setsid().map_err(std::io::Error::from)?;
            nix::sys::prctl::set_no_new_privs().map_err(std::io::Error::from)?;
            let _ = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0);
            nix::sys::resource::setrlimit(
                nix::sys::resource::Resource::RLIMIT_AS,
                address_space,
                address_space,
            )
            .map_err(std::io::Error::from)?;
            nix::sys::resource::setrlimit(
                nix::sys::resource::Resource::RLIMIT_CPU,
                cpu_seconds,
                cpu_seconds,
            )
            .map_err(std::io::Error::from)?;
            nix::sys::resource::setrlimit(
                nix::sys::resource::Resource::RLIMIT_FSIZE,
                file_size,
                file_size,
            )
            .map_err(std::io::Error::from)?;
            nix::sys::resource::setrlimit(
                nix::sys::resource::Resource::RLIMIT_NOFILE,
                open_files,
                open_files,
            )
            .map_err(std::io::Error::from)?;
            Ok(())
        });
    }
}
