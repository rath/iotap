//! Recordings: everything a session consumed, in order, so it can be replayed without root.
//!
//! Layout: the magic `IOTAPREC`, a little-endian `u32` version, then frames of
//! `[tag: u8][length: u32 LE][payload]`. Batches of kdebug records carry the raw 64-byte records
//! in little-endian order, and batches of Linux records the records one after another as the
//! eBPF program lays them out; every other payload is JSON. The header names the system the
//! recording comes from; version 1 recordings, which do not, all come from macOS. A recording
//! replays only on the operating system it was made on, whose numbers its calls use.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::model::Target;
use crate::session::{Input, Process, SessionInfo};
use crate::trace::kdebug::KdBuf;
use crate::trace::linux;
use crate::trace::procs::{Described, ProcSource, Snapshot};
use crate::trace::{Records, System};

const MAGIC: &[u8; 8] = b"IOTAPREC";
const VERSION: u32 = 2;
/// Refuses frames larger than this, so a corrupt length cannot exhaust memory.
const MAX_FRAME: usize = 1 << 30;

const TAG_HEADER: u8 = 1;
const TAG_KDEBUG_RECORDS: u8 = 2;
const TAG_ATTACHED: u8 = 3;
const TAG_EXEC: u8 = 4;
const TAG_EXITED: u8 = 5;
const TAG_STOPPED: u8 = 6;
const TAG_SNAPSHOT: u8 = 7;
const TAG_DESCRIBE: u8 = 8;
const TAG_WATERMARK: u8 = 9;
const TAG_LINUX_RECORDS: u8 = 10;

#[derive(Serialize, Deserialize)]
struct Header {
    info: SessionInfo,
    created_by: String,
}

#[derive(Serialize, Deserialize)]
struct ExecFrame {
    pid: i32,
    path: String,
}

#[derive(Serialize, Deserialize)]
struct ExitedFrame {
    pid: i32,
    /// Absent from recordings made before exits carried a time; 0 applies the exit at once,
    /// as iotap did then.
    #[serde(default)]
    ticks: u64,
}

#[derive(Serialize, Deserialize)]
struct StoppedFrame {
    ticks: u64,
}

#[derive(Serialize, Deserialize)]
struct WatermarkFrame {
    ticks: u64,
}

/// Written with borrowed answers, read back as owned ones.
#[derive(Serialize, Deserialize)]
struct SnapshotFrame<T> {
    pid: i32,
    answer: Option<T>,
}

#[derive(Serialize, Deserialize)]
struct DescribeFrame<T> {
    pid: i32,
    fd: i32,
    answer: Option<T>,
    /// Absent from recordings made before answers were checked against the trace.
    #[serde(default)]
    at: u64,
}

/// Writes a recording.
#[derive(Debug)]
pub struct Recorder<W: Write> {
    out: W,
}

impl Recorder<BufWriter<File>> {
    pub fn create(path: &Path, info: &SessionInfo) -> io::Result<Self> {
        Self::new(BufWriter::with_capacity(1 << 20, File::create(path)?), info)
    }
}

impl<W: Write> Recorder<W> {
    /// Writes the file header and the session facts.
    pub fn new(mut out: W, info: &SessionInfo) -> io::Result<Self> {
        out.write_all(MAGIC)?;
        out.write_all(&VERSION.to_le_bytes())?;
        let mut recorder = Self { out };
        let header = Header {
            info: info.clone(),
            created_by: format!("iotap {}", env!("CARGO_PKG_VERSION")),
        };
        recorder.json(TAG_HEADER, &header)?;
        Ok(recorder)
    }

    pub fn input(&mut self, input: &Input) -> io::Result<()> {
        match input {
            Input::Records(Records::Kdebug(records)) => {
                let mut payload = Vec::with_capacity(records.len() * KdBuf::SIZE);
                for record in records {
                    payload.extend_from_slice(&record.to_le_bytes());
                }
                self.frame(TAG_KDEBUG_RECORDS, &payload)
            }
            Input::Records(Records::Linux(records)) => {
                let mut payload = Vec::with_capacity(records.len() * linux::HEADER);
                for record in records {
                    record.write(&mut payload);
                }
                self.frame(TAG_LINUX_RECORDS, &payload)
            }
            Input::Attached(process) => self.json(TAG_ATTACHED, process),
            Input::Exec { pid, path } => self.json(
                TAG_EXEC,
                &ExecFrame {
                    pid: *pid,
                    path: path.clone(),
                },
            ),
            Input::Exited { pid, ticks } => self.json(
                TAG_EXITED,
                &ExitedFrame {
                    pid: *pid,
                    ticks: *ticks,
                },
            ),
            Input::Stopped { ticks } => self.json(TAG_STOPPED, &StoppedFrame { ticks: *ticks }),
            Input::Watermark { ticks } => self.json(TAG_WATERMARK, &WatermarkFrame { ticks: *ticks }),
        }
    }

    fn snapshot(&mut self, pid: i32, answer: Option<&Snapshot>) -> io::Result<()> {
        self.json(TAG_SNAPSHOT, &SnapshotFrame { pid, answer })
    }

    fn describe(&mut self, pid: i32, fd: i32, described: &Described) -> io::Result<()> {
        self.json(
            TAG_DESCRIBE,
            &DescribeFrame {
                pid,
                fd,
                answer: described.target.as_ref(),
                at: described.at,
            },
        )
    }

    /// Flushes and returns the writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.out.flush()?;
        Ok(self.out)
    }

    fn json<T: Serialize>(&mut self, tag: u8, value: &T) -> io::Result<()> {
        let payload = serde_json::to_vec(value).map_err(io::Error::other)?;
        self.frame(tag, &payload)
    }

    fn frame(&mut self, tag: u8, payload: &[u8]) -> io::Result<()> {
        let len = u32::try_from(payload.len()).map_err(|_| io::Error::other("frame too large"))?;
        self.out.write_all(&[tag])?;
        self.out.write_all(&len.to_le_bytes())?;
        self.out.write_all(payload)
    }
}

/// A process source that records every answer of the source it wraps. A failed write stops
/// the recording; tracing carries on and the error is kept for the caller.
#[derive(Debug)]
pub struct Recording<P, W: Write> {
    pub source: P,
    recorder: Option<Recorder<W>>,
    error: Option<io::Error>,
}

impl<P: ProcSource, W: Write> Recording<P, W> {
    pub fn new(source: P, recorder: Option<Recorder<W>>) -> Self {
        Self {
            source,
            recorder,
            error: None,
        }
    }

    /// Records one reader input.
    pub fn input(&mut self, input: &Input) {
        self.write(|recorder| recorder.input(input));
    }

    /// The first write error, if recording failed.
    pub fn error(&self) -> Option<&io::Error> {
        self.error.as_ref()
    }

    /// Flushes the recording; returns the first error seen.
    pub fn finish(self) -> io::Result<()> {
        if let Some(err) = self.error {
            return Err(err);
        }
        match self.recorder {
            Some(recorder) => recorder.finish().map(drop),
            None => Ok(()),
        }
    }

    fn write(&mut self, op: impl FnOnce(&mut Recorder<W>) -> io::Result<()>) {
        if let Some(recorder) = self.recorder.as_mut()
            && let Err(err) = op(recorder)
        {
            self.recorder = None;
            self.error = Some(err);
        }
    }
}

impl<P: ProcSource, W: Write> ProcSource for Recording<P, W> {
    fn snapshot(&mut self, pid: i32) -> Option<Snapshot> {
        let answer = self.source.snapshot(pid);
        self.write(|recorder| recorder.snapshot(pid, answer.as_ref()));
        answer
    }

    fn describe(&mut self, pid: i32, fd: i32) -> Described {
        let described = self.source.describe(pid, fd);
        self.write(|recorder| recorder.describe(pid, fd, &described));
        described
    }
}

/// Recorded process-source answers, replayed in the order they were given.
#[derive(Debug, Default)]
pub struct Answers {
    snapshots: HashMap<i32, VecDeque<Option<Snapshot>>>,
    describes: HashMap<(i32, i32), VecDeque<Described>>,
}

impl ProcSource for Answers {
    fn snapshot(&mut self, pid: i32) -> Option<Snapshot> {
        self.snapshots
            .get_mut(&pid)
            .and_then(VecDeque::pop_front)
            .flatten()
    }

    fn describe(&mut self, pid: i32, fd: i32) -> Described {
        self.describes
            .get_mut(&(pid, fd))
            .and_then(VecDeque::pop_front)
            .unwrap_or_else(|| Described::settled(None))
    }
}

/// A parsed recording.
#[derive(Debug)]
pub struct Replay {
    pub info: SessionInfo,
    pub created_by: String,
    pub inputs: Vec<Input>,
    pub answers: Answers,
    /// The file ended inside a frame, as when iotap was killed while recording.
    pub truncated: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("cannot read the recording")]
    Io(#[from] io::Error),
    #[error("not an iotap recording")]
    BadMagic,
    #[error("unsupported recording version {0}; this iotap reads versions 1 to {VERSION}")]
    Version(u32),
    #[error("the recording has no header")]
    NoHeader,
    #[error("corrupt frame {index} (tag {tag}): {reason}")]
    Corrupt { index: usize, tag: u8, reason: String },
    #[error(
        "it was made on {made_on}; replay it on {made_on}, as its calls use that system's numbers for errors, address families and flags"
    )]
    OtherSystem { made_on: &'static str },
}

/// Refuses a recording made on another operating system than this one.
pub fn check_system(info: &SessionInfo) -> Result<(), ReplayError> {
    if info.system.same_os(System::HOST) {
        Ok(())
    } else {
        Err(ReplayError::OtherSystem {
            made_on: info.system.os_name(),
        })
    }
}

pub fn read(path: &Path) -> Result<Replay, ReplayError> {
    parse(BufReader::with_capacity(1 << 20, File::open(path)?))
}

pub fn parse(mut input: impl Read) -> Result<Replay, ReplayError> {
    let mut magic = [0u8; 8];
    input.read_exact(&mut magic).map_err(|_| ReplayError::BadMagic)?;
    if &magic != MAGIC {
        return Err(ReplayError::BadMagic);
    }
    let mut version = [0u8; 4];
    input
        .read_exact(&mut version)
        .map_err(|_| ReplayError::BadMagic)?;
    let version = u32::from_le_bytes(version);
    if !(1..=VERSION).contains(&version) {
        return Err(ReplayError::Version(version));
    }

    let mut header: Option<Header> = None;
    let mut inputs = Vec::new();
    let mut answers = Answers::default();
    let mut truncated = false;
    let mut index = 0;
    loop {
        let (tag, payload) = match next_frame(&mut input) {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                truncated = true;
                break;
            }
            Err(err) => return Err(err.into()),
        };
        let corrupt = |reason: String| ReplayError::Corrupt { index, tag, reason };
        match tag {
            TAG_HEADER => header = Some(json(&payload).map_err(corrupt)?),
            TAG_KDEBUG_RECORDS => inputs.push(Input::Records(Records::Kdebug(
                kdebug_records(&payload).map_err(corrupt)?,
            ))),
            TAG_LINUX_RECORDS => inputs.push(Input::Records(Records::Linux(
                linux_records(&payload).map_err(corrupt)?,
            ))),
            TAG_ATTACHED => inputs.push(Input::Attached(json::<Process>(&payload).map_err(corrupt)?)),
            TAG_EXEC => {
                let frame: ExecFrame = json(&payload).map_err(corrupt)?;
                inputs.push(Input::Exec {
                    pid: frame.pid,
                    path: frame.path,
                });
            }
            TAG_EXITED => {
                let frame: ExitedFrame = json(&payload).map_err(corrupt)?;
                inputs.push(Input::Exited {
                    pid: frame.pid,
                    ticks: frame.ticks,
                });
            }
            TAG_STOPPED => {
                inputs.push(Input::Stopped {
                    ticks: json::<StoppedFrame>(&payload).map_err(corrupt)?.ticks,
                });
            }
            TAG_SNAPSHOT => {
                let frame: SnapshotFrame<Snapshot> = json(&payload).map_err(corrupt)?;
                answers
                    .snapshots
                    .entry(frame.pid)
                    .or_default()
                    .push_back(frame.answer);
            }
            TAG_DESCRIBE => {
                let frame: DescribeFrame<Target> = json(&payload).map_err(corrupt)?;
                answers
                    .describes
                    .entry((frame.pid, frame.fd))
                    .or_default()
                    .push_back(Described {
                        target: frame.answer,
                        at: frame.at,
                    });
            }
            TAG_WATERMARK => inputs.push(Input::Watermark {
                ticks: json::<WatermarkFrame>(&payload).map_err(corrupt)?.ticks,
            }),
            // Frames from newer versions of the same layout are skipped.
            _ => {}
        }
        index += 1;
    }
    let header = header.ok_or(ReplayError::NoHeader)?;
    Ok(Replay {
        info: header.info,
        created_by: header.created_by,
        inputs,
        answers,
        truncated,
    })
}

fn kdebug_records(payload: &[u8]) -> Result<Vec<KdBuf>, String> {
    if !payload.len().is_multiple_of(KdBuf::SIZE) {
        return Err(format!(
            "{} bytes is not a whole number of records",
            payload.len()
        ));
    }
    Ok(payload
        .chunks_exact(KdBuf::SIZE)
        .map(|chunk| {
            let mut bytes = [0u8; KdBuf::SIZE];
            bytes.copy_from_slice(chunk);
            KdBuf::from_le_bytes(&bytes)
        })
        .collect())
}

fn linux_records(payload: &[u8]) -> Result<Vec<linux::Record>, String> {
    let mut records = Vec::new();
    let mut rest = payload;
    while !rest.is_empty() {
        let at = payload.len() - rest.len();
        let (record, len) =
            linux::Record::parse(rest).ok_or_else(|| format!("no whole record at byte {at}"))?;
        records.push(record);
        rest = &rest[len..];
    }
    Ok(records)
}

/// Reads one frame; `Ok(None)` at a clean end of file.
fn next_frame(input: &mut impl Read) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut tag = [0u8; 1];
    if input.read(&mut tag)? == 0 {
        return Ok(None);
    }
    let mut len = [0u8; 4];
    input.read_exact(&mut len)?;
    let len = usize::try_from(u32::from_le_bytes(len)).unwrap_or(usize::MAX);
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes"),
        ));
    }
    let mut payload = vec![0u8; len];
    input.read_exact(&mut payload)?;
    Ok(Some((tag[0], payload)))
}

fn json<T: DeserializeOwned>(payload: &[u8]) -> Result<T, String> {
    serde_json::from_slice(payload).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Endpoint, Proto};
    use crate::session::{Collect, Filter, Session};
    use crate::sys::time::{ClockAnchor, Timebase};
    use crate::trace::kdebug::pairing::PathRecords;
    use crate::trace::kdebug::synth::Synth;
    use crate::trace::procs::Fixed;

    fn fixture() -> (SessionInfo, Fixed, Vec<Input>) {
        let info = SessionInfo {
            timebase: Timebase { numer: 125, denom: 3 },
            anchor: ClockAnchor {
                ticks: 10_000,
                unix_nanos: 1_790_000_000_000_000_000,
            },
            processes: vec![Process {
                pid: 300,
                name: "curl".into(),
            }],
            path_records: PathRecords::Whole,
            system: System::Macos,
        };
        let mut procs = Fixed::default();
        procs.snapshots.insert(
            300,
            Snapshot {
                fds: vec![],
                cwd: Some("/tmp".into()),
            },
        );
        let peer = Endpoint {
            proto: Proto::Tcp,
            local: Some("10.0.0.5:61000".parse().unwrap()),
            remote: Some("93.184.216.34:443".parse().unwrap()),
            path: None,
        };
        procs.targets.insert((300, 5), Target::Socket(peer));
        let mut synth = Synth::new(20_000, 240);
        let mut records = synth.open(1, 300, "out.html", 4);
        records.extend(synth.io(2, 300, 133, 5, 517, 517));
        records.extend(synth.io(2, 300, 29, 5, 65_536, 1_256));
        records.extend(synth.io(1, 300, 4, 4, 1_256, 1_256));
        let gone = synth.now();
        let inputs = vec![
            Input::Records(Records::Kdebug(records)),
            Input::Exited {
                pid: 300,
                ticks: gone,
            },
            Input::Stopped { ticks: gone + 24_000 },
        ];
        (info, procs, inputs)
    }

    fn run(info: SessionInfo, src: &mut dyn ProcSource, inputs: &[Input]) -> (Collect, String) {
        let mut session = Session::new(info, Filter::ALL, src);
        let mut sink = Collect::default();
        for input in inputs {
            session.handle(input, src, &mut sink).unwrap();
        }
        let summary = serde_json::to_string(&session.summary()).unwrap();
        (sink, summary)
    }

    #[test]
    fn replay_reproduces_the_live_session() {
        let (info, procs, inputs) = fixture();
        let recorder = Recorder::new(Vec::new(), &info).unwrap();
        let mut recording = Recording::new(procs, Some(recorder));
        let mut session = Session::new(info.clone(), Filter::ALL, &mut recording);
        let mut live = Collect::default();
        for input in &inputs {
            recording.input(input);
            session.handle(input, &mut recording, &mut live).unwrap();
        }
        let live_summary = serde_json::to_string(&session.summary()).unwrap();
        let bytes = recording.recorder.take().unwrap().finish().unwrap();

        let mut replay = parse(bytes.as_slice()).unwrap();
        assert!(!replay.truncated);
        assert_eq!(replay.info, info);
        assert_eq!(replay.inputs, inputs);
        let (replayed, replay_summary) = run(replay.info.clone(), &mut replay.answers, &replay.inputs);
        assert_eq!(replayed.events, live.events);
        assert_eq!(replayed.notices, live.notices);
        assert_eq!(replay_summary, live_summary);
        assert_eq!(live.events.len(), 3);
        assert_eq!(
            live.events[0].target.to_string(),
            "tcp 10.0.0.5:61000 -> 93.184.216.34:443"
        );
        assert_eq!(live.events[2].target.to_string(), "/tmp/out.html");
    }

    #[test]
    fn keeps_answer_times_and_watermarks() {
        let (info, mut procs, _) = fixture();
        procs.answered_at = 77_000;
        let mut recording = Recording::new(procs, Some(Recorder::new(Vec::new(), &info).unwrap()));
        let answer = recording.describe(300, 5);
        recording.input(&Input::Watermark { ticks: 78_000 });
        let mut bytes = recording.recorder.take().unwrap().finish().unwrap();
        // A describe frame from before answer times were kept.
        let old = br#"{"pid":300,"fd":5,"answer":null}"#;
        bytes.push(TAG_DESCRIBE);
        bytes.extend_from_slice(&u32::try_from(old.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(old);

        let mut replay = parse(bytes.as_slice()).unwrap();
        assert_eq!(replay.inputs, [Input::Watermark { ticks: 78_000 }]);
        assert_eq!(replay.answers.describe(300, 5), answer);
        assert_eq!(answer.at, 77_000);
        assert_eq!(replay.answers.describe(300, 5), Described::settled(None));
    }

    #[test]
    fn exits_keep_their_time_and_older_ones_count_at_once() {
        let (info, _, _) = fixture();
        let mut recorder = Recorder::new(Vec::new(), &info).unwrap();
        let exit = Input::Exited {
            pid: 300,
            ticks: 77_000,
        };
        recorder.input(&exit).unwrap();
        let mut bytes = recorder.finish().unwrap();
        // An exit frame from before exits carried a time.
        let old = br#"{"pid":301}"#;
        bytes.push(TAG_EXITED);
        bytes.extend_from_slice(&u32::try_from(old.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(old);

        let replay = parse(bytes.as_slice()).unwrap();
        assert_eq!(replay.inputs, [exit, Input::Exited { pid: 301, ticks: 0 }]);
    }

    #[test]
    fn truncated_recordings_keep_complete_frames() {
        let (info, _, inputs) = fixture();
        let mut recorder = Recorder::new(Vec::new(), &info).unwrap();
        for input in &inputs {
            recorder.input(input).unwrap();
        }
        let bytes = recorder.finish().unwrap();
        let replay = parse(&bytes[..bytes.len() - 3]).unwrap();
        assert!(replay.truncated);
        assert_eq!(replay.inputs.len(), 2);
    }

    #[test]
    fn version_1_recordings_come_from_macos() {
        let (info, _, _) = fixture();
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        let mut header = serde_json::to_value(Header {
            info: info.clone(),
            created_by: "iotap 0.1.0".into(),
        })
        .unwrap();
        header["info"].as_object_mut().unwrap().remove("system");
        let payload = serde_json::to_vec(&header).unwrap();
        bytes.push(TAG_HEADER);
        bytes.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(&payload);
        let replay = parse(bytes.as_slice()).unwrap();
        assert_eq!(replay.info, info);
        assert_eq!(replay.info.system, System::Macos);
    }

    #[test]
    fn replays_only_on_the_system_that_made_them() {
        let (mut info, _, _) = fixture();
        info.system = System::HOST;
        assert!(check_system(&info).is_ok());
        info.system = match System::HOST {
            System::Macos => System::LinuxX86_64,
            System::LinuxAarch64 | System::LinuxX86_64 => System::Macos,
        };
        let err = check_system(&info).unwrap_err();
        assert!(err.to_string().starts_with("it was made on "), "{err}");
        assert_eq!(
            serde_json::to_string(&[System::LinuxAarch64, System::LinuxX86_64]).unwrap(),
            r#"["linux_aarch64","linux_x86_64"]"#
        );
    }

    #[test]
    fn linux_records_survive_a_recording() {
        let (mut info, _, _) = fixture();
        info.system = System::LinuxAarch64;
        let mut synth = linux::synth::Synth::new(info.system, 20_000, 240);
        let records = vec![
            synth.open(1, 300, "/tmp/out.html", 4),
            synth.io(1, 300, "write", 4, 10, 10),
            synth.lost(2),
            synth.exit(300),
        ];
        let inputs = vec![
            Input::Records(Records::Linux(records)),
            Input::Watermark { ticks: synth.now() },
        ];
        let mut recorder = Recorder::new(Vec::new(), &info).unwrap();
        for input in &inputs {
            recorder.input(input).unwrap();
        }
        let mut bytes = recorder.finish().unwrap();
        let replay = parse(bytes.as_slice()).unwrap();
        assert_eq!((replay.info, replay.inputs), (info, inputs));

        // A batch whose last record is cut short.
        let mut cut = Vec::new();
        synth.open(1, 300, "/tmp/x", 5).write(&mut cut);
        let whole = cut.len();
        cut.pop();
        bytes.push(TAG_LINUX_RECORDS);
        bytes.extend_from_slice(&u32::try_from(cut.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(&cut);
        let err = parse(bytes.as_slice()).unwrap_err();
        assert!(
            err.to_string().ends_with("no whole record at byte 0"),
            "{err} ({whole} bytes)"
        );
    }

    #[test]
    fn rejects_foreign_files() {
        assert!(matches!(parse(&b"GIF89a..."[..]), Err(ReplayError::BadMagic)));
        let mut wrong = MAGIC.to_vec();
        wrong.extend_from_slice(&9u32.to_le_bytes());
        assert!(matches!(parse(wrong.as_slice()), Err(ReplayError::Version(9))));
        let mut empty = MAGIC.to_vec();
        empty.extend_from_slice(&VERSION.to_le_bytes());
        assert!(matches!(parse(empty.as_slice()), Err(ReplayError::NoHeader)));
    }
}
