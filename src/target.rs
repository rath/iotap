//! Resolves command-line targets to running processes.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::session::Process;
use crate::sys::proc::{self, ProcInfo};

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

/// A traced process: what names it, and what tells it apart from a later process with the same
/// pid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tracked {
    pub pid: i32,
    pub name: String,
    pub start: (u64, u64),
    pub exe: Option<String>,
    /// Its first argument as it stands now: the command or path it was started as, unless it has
    /// rewritten it since.
    pub arg0: Option<String>,
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
        let info = proc::info(pid)?;
        Some(Self {
            pid,
            name: info.name,
            start: info.start,
            exe: proc::exe_path(pid),
            arg0: proc::arg0(pid),
        })
    }

    /// True when `wanted` names the process, ignoring case: its name, or the file name of its
    /// executable or of its first argument. The macOS kernel names a process after the file it
    /// runs, links followed, while the first argument keeps the command it was started as, which
    /// is what `pgrep` and `killall` go by there.
    pub fn is_named(&self, wanted: &str) -> bool {
        self.names().any(|name| name.eq_ignore_ascii_case(wanted))
    }

    /// Its name, then the file names of its executable and of its first argument.
    fn names(&self) -> impl Iterator<Item = &str> {
        [
            Some(self.name.as_str()),
            self.exe.as_deref().map(file_name),
            self.arg0.as_deref().map(file_name),
        ]
        .into_iter()
        .flatten()
    }
}

/// The part of `path` after its last slash.
fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[derive(Debug, thiserror::Error)]
pub enum TargetError {
    #[error("no process with pid {0}")]
    NoPid(i32),
    #[error("no process named '{name}'{hint}")]
    NoName { name: String, hint: String },
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
                let matched: Vec<Tracked> = all.iter().filter(|t| t.is_named(name)).cloned().collect();
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

/// Every running process descended from one in `roots`, parents before their children. Left
/// out are iotap (`own_pid`) and the processes it runs under, such as the `sudo` that started
/// it: iotap descends from the shell it was started from, and a process that relays its output,
/// as `sudo` does through a pseudo-terminal, would have iotap trace its own output without end.
/// Their other children are not left out.
pub fn descendants(roots: &[i32], own_pid: i32) -> Vec<Tracked> {
    let running: Vec<ProcInfo> = proc::list_pids().into_iter().filter_map(proc::info).collect();
    family(&running, roots, own_pid)
        .into_iter()
        .filter_map(Tracked::probe)
        .collect()
}

/// The pids of the processes in `running` that descend from one in `roots`, in the order and
/// with the exceptions of [`descendants`].
fn family(running: &[ProcInfo], roots: &[i32], own_pid: i32) -> Vec<i32> {
    let parents: HashMap<i32, i32> = running.iter().map(|info| (info.pid, info.parent)).collect();
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
    for info in running {
        children.entry(info.parent).or_default().push(info.pid);
    }
    // The processes iotap runs under, up to the first that is not running.
    let mut above = HashSet::new();
    let mut pid = own_pid;
    while let Some(&parent) = parents.get(&pid) {
        if !above.insert(parent) {
            break;
        }
        pid = parent;
    }
    let mut seen: HashSet<i32> = roots.iter().copied().collect();
    let mut queue: VecDeque<i32> = roots.iter().copied().collect();
    let mut found = Vec::new();
    while let Some(pid) = queue.pop_front() {
        for &child in children.get(&pid).into_iter().flatten() {
            // What iotap starts is never traced, so neither is anything below it.
            if child == own_pid || !seen.insert(child) {
                continue;
            }
            if !above.contains(&child) {
                found.push(child);
            }
            queue.push_back(child);
        }
    }
    found
}

/// Every running process except `own_pid`.
fn all_processes(own_pid: i32) -> Vec<Tracked> {
    proc::list_pids()
        .into_iter()
        .filter(|&pid| pid != own_pid)
        .filter_map(Tracked::probe)
        .collect()
}

/// Names of processes that contain `wanted`, ignoring case, to offer in its place.
fn similar(all: &[Tracked], wanted: &str) -> String {
    let wanted = wanted.to_lowercase();
    let mut close: Vec<String> = all
        .iter()
        .filter_map(|t| {
            let name = t.names().find(|name| name.to_lowercase().contains(&wanted))?;
            Some(format!("{} ({})", printable(name), t.pid))
        })
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

/// `name` with each control character written as `?`: a process can give itself any first
/// argument, and this one is shown on a terminal.
fn printable(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::proc::Sleeper;

    fn process(name: &str, exe: Option<&str>, arg0: Option<&str>) -> Tracked {
        Tracked {
            pid: 1,
            name: name.into(),
            start: (0, 0),
            exe: exe.map(Into::into),
            arg0: arg0.map(Into::into),
        }
    }

    #[test]
    fn parses_specs() {
        assert_eq!(Spec::parse("123", false), Spec::Pid(123));
        assert_eq!(Spec::parse("123", true), Spec::Name("123".into()));
        assert_eq!(Spec::parse("-4", false), Spec::Name("-4".into()));
        assert_eq!(Spec::parse("Safari", false), Spec::Name("Safari".into()));
    }

    #[test]
    fn matches_names_ignoring_case() {
        assert!(process("Safari", None, None).is_named("safari"));
        let helper = process(
            "Google Chrome He",
            Some("/Applications/x/Google Chrome Helper"),
            None,
        );
        assert!(helper.is_named("Google Chrome Helper"));
        let chrome = process("Google Chrome", Some("/Applications/Google Chrome"), None);
        assert!(!chrome.is_named("chrome"));
    }

    #[test]
    fn matches_the_command_a_process_was_started_as() {
        // Started through a link to a file named after its version, as Claude Code's is.
        let linked = process(
            "2.1.282",
            Some("/Users/u/.local/share/claude/versions/2.1.282"),
            Some("claude"),
        );
        assert!(linked.is_named("Claude"));
        assert!(linked.is_named("2.1.282"));
        let by_path = process("sleep", Some("/bin/sleep"), Some("/tmp/links/nap"));
        assert!(by_path.is_named("nap"));
        assert!(!by_path.is_named("links"));
        // A title the process gave itself.
        let titled = process("postgres", None, Some("postgres: checkpointer"));
        assert!(titled.is_named("postgres: checkpointer"));
        assert!(!titled.is_named("checkpointer"));
    }

    #[test]
    fn resolves_a_process_by_the_command_it_was_started_as() {
        let me = i32::try_from(std::process::id()).unwrap();
        let command = format!("iotap-test-{me}-nap");
        let sleeper = Sleeper::start(&command);
        let found = resolve(&[Spec::Name(command.clone())], me).unwrap();
        assert_eq!(found.iter().map(|t| t.pid).collect::<Vec<_>>(), [sleeper.pid()]);
        // Part of the command names no process, but the process is offered.
        let missed = resolve(&[Spec::Name(format!("iotap-test-{me}"))], me).unwrap_err();
        let offer = format!("; similar: {command} ({})", sleeper.pid());
        assert!(missed.to_string().ends_with(&offer), "{missed}");
    }

    #[test]
    fn offers_names_with_control_characters_written_as_question_marks() {
        let mut titled = process("sleep", None, Some("nap\x1b[31m"));
        titled.pid = 7;
        assert_eq!(similar(&[titled], "NAP"), "; similar: nap?[31m (7)");
    }

    /// Running processes, each given as its pid and its parent's.
    fn running(tree: &[(i32, i32)]) -> Vec<ProcInfo> {
        tree.iter()
            .map(|&(pid, parent)| ProcInfo {
                pid,
                name: format!("p{pid}"),
                start: (0, 0),
                parent,
            })
            .collect()
    }

    #[test]
    fn a_family_is_everything_below_its_roots() {
        // 10 started 11 and 12, 12 started 13, and 20 is no relative.
        let tree = running(&[(1, 0), (10, 1), (11, 10), (12, 10), (13, 12), (20, 1)]);
        assert_eq!(family(&tree, &[10], 99), [11, 12, 13]);
        assert_eq!(
            family(&tree, &[12, 10], 99),
            [13, 11],
            "roots are not their own descendants"
        );
        assert!(family(&tree, &[20], 99).is_empty());
        assert!(family(&tree, &[99], 99).is_empty());
        // Parents that name each other, which no kernel reports, end the searches all the same.
        let circle = running(&[(5, 6), (6, 5)]);
        assert_eq!(family(&circle, &[5], 99), [6]);
        assert!(family(&circle, &[5], 5).is_empty(), "6 is above iotap");
    }

    #[test]
    fn a_family_leaves_out_iotap_and_what_it_runs_under() {
        // A shell (10) ran sudo (11), which runs iotap (12), which runs 13; the shell's job 14
        // runs 15.
        let tree = running(&[(1, 0), (10, 1), (11, 10), (12, 11), (13, 12), (14, 10), (15, 14)]);
        assert_eq!(family(&tree, &[10], 12), [14, 15]);
        assert_eq!(family(&tree, &[1], 12), [14, 15]);
        assert_eq!(family(&tree, &[1], 99), [10, 11, 14, 12, 15, 13]);
    }

    #[test]
    fn finds_running_descendants_but_never_iotap() {
        let me = i32::try_from(std::process::id()).unwrap();
        let sleeper = Sleeper::start(&format!("iotap-family-{me}"));
        let pids = |found: Vec<Tracked>| found.iter().map(|t| t.pid).collect::<Vec<_>>();
        assert!(pids(descendants(&[me], i32::MAX)).contains(&sleeper.pid()));
        // With the test in iotap's place, its parent's descendants leave out the test and what
        // it started.
        let parent = std::os::unix::process::parent_id().cast_signed();
        let below = pids(descendants(&[parent], me));
        assert!(
            !below.contains(&me) && !below.contains(&sleeper.pid()),
            "{below:?}"
        );
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
