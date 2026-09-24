//! Resolves command-line targets to running processes.

use crate::session::Process;
use crate::sys::proc as libproc;

/// A target as given on the command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Spec {
    Pid(i32),
    Name(String),
}

impl Spec {
    /// Numeric arguments are pids unless `force_names` is set.
    pub fn parse(raw: &str, force_names: bool) -> Self {
        match raw.parse::<i32>() {
            Ok(pid) if !force_names && pid > 0 => Self::Pid(pid),
            _ => Self::Name(raw.to_owned()),
        }
    }
}

/// A traced process and what tells it apart from a later process with the same pid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tracked {
    pub pid: i32,
    pub name: String,
    pub start: (u64, u64),
    pub exe: Option<String>,
}

impl Tracked {
    pub fn process(&self) -> Process {
        Process {
            pid: self.pid,
            name: self.name.clone(),
        }
    }

    /// Reads the current facts of `pid`; `None` if it is not running.
    pub fn probe(pid: i32) -> Option<Self> {
        let info = libproc::info(pid)?;
        Some(Self {
            pid,
            name: info.name,
            start: info.start,
            exe: libproc::exe_path(pid),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TargetError {
    #[error("no process with pid {0}")]
    NoPid(i32),
    #[error("no process named '{name}'{hint}")]
    NoName { name: String, hint: String },
}

/// True when `wanted` names the process, ignoring case: its name or its executable's file name.
pub fn name_matches(wanted: &str, name: &str, exe: Option<&str>) -> bool {
    name.eq_ignore_ascii_case(wanted)
        || exe
            .and_then(|p| p.rsplit('/').next())
            .is_some_and(|b| b.eq_ignore_ascii_case(wanted))
}

/// Resolves every spec, excluding `own_pid`. Each name must match at least one process.
pub fn resolve(specs: &[Spec], own_pid: i32) -> Result<Vec<Tracked>, TargetError> {
    let mut tracked: Vec<Tracked> = Vec::new();
    let mut everyone: Option<Vec<Tracked>> = None;
    for spec in specs {
        let found = match spec {
            Spec::Pid(pid) => vec![Tracked::probe(*pid).ok_or(TargetError::NoPid(*pid))?],
            Spec::Name(name) => {
                let all = everyone.get_or_insert_with(|| all_processes(own_pid));
                let matched: Vec<Tracked> = all
                    .iter()
                    .filter(|t| name_matches(name, &t.name, t.exe.as_deref()))
                    .cloned()
                    .collect();
                if matched.is_empty() {
                    return Err(TargetError::NoName {
                        name: name.clone(),
                        hint: similar(all, name),
                    });
                }
                matched
            }
        };
        for process in found {
            if !tracked.iter().any(|t| t.pid == process.pid) {
                tracked.push(process);
            }
        }
    }
    Ok(tracked)
}

/// Every running process except `own_pid`.
pub fn all_processes(own_pid: i32) -> Vec<Tracked> {
    libproc::list_pids()
        .into_iter()
        .filter(|&pid| pid != own_pid)
        .filter_map(Tracked::probe)
        .collect()
}

fn similar(all: &[Tracked], wanted: &str) -> String {
    let wanted = wanted.to_lowercase();
    let mut close: Vec<String> = all
        .iter()
        .filter(|t| t.name.to_lowercase().contains(&wanted))
        .map(|t| format!("{} ({})", t.name, t.pid))
        .collect();
    close.sort();
    close.dedup();
    if close.is_empty() {
        return String::new();
    }
    let more = close.len().saturating_sub(5);
    close.truncate(5);
    let tail = if more > 0 {
        format!(", and {more} more")
    } else {
        String::new()
    };
    format!("; similar: {}{tail}", close.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_specs() {
        assert_eq!(Spec::parse("123", false), Spec::Pid(123));
        assert_eq!(Spec::parse("123", true), Spec::Name("123".into()));
        assert_eq!(Spec::parse("-4", false), Spec::Name("-4".into()));
        assert_eq!(Spec::parse("Safari", false), Spec::Name("Safari".into()));
    }

    #[test]
    fn matches_names_ignoring_case() {
        assert!(name_matches("safari", "Safari", None));
        assert!(name_matches(
            "Google Chrome Helper",
            "Google Chrome He",
            Some("/Applications/x/Google Chrome Helper")
        ));
        assert!(!name_matches(
            "chrome",
            "Google Chrome",
            Some("/Applications/Google Chrome")
        ));
    }

    #[test]
    fn resolves_own_parent_and_rejects_missing() {
        let me = i32::try_from(std::process::id()).unwrap();
        let parent = std::os::unix::process::parent_id().cast_signed();
        let found = resolve(&[Spec::Pid(parent), Spec::Pid(parent)], me).unwrap();
        assert_eq!(found.len(), 1, "duplicates collapse");
        assert!(matches!(
            resolve(&[Spec::Pid(i32::MAX)], me),
            Err(TargetError::NoPid(_))
        ));
        let err = resolve(&[Spec::Name("no-such-process-iotap".into())], me).unwrap_err();
        assert!(err.to_string().starts_with("no process named"));
    }
}
