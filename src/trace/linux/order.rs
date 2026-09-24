//! Puts the records of the eBPF program in time order.
//!
//! Records reach the ring buffer nearly, but not exactly, in time order: a record is stamped
//! when its call returns and written a moment later, so a CPU can write a record stamped after
//! one that another CPU is still writing. The reader therefore holds records back until it
//! knows that every record stamped before them has reached it, and passes them on sorted. The
//! counts of dropped records they carry tell it where the ring buffer overflowed.

use std::collections::VecDeque;

use super::{Event, Record};

/// Records taken from the ring buffer and not yet passed on, in time order.
#[derive(Debug, Default)]
pub struct Order {
    held: VecDeque<Record>,
    /// The program's count of dropped records as last passed on; it wraps as that count does.
    announced: u32,
}

impl Order {
    /// Takes a record in the order the ring buffer gave it.
    pub fn hold(&mut self, record: Record) {
        // Most records come last in time; one that was written late goes back to its place,
        // after any stamped at the same time.
        if self.held.back().is_none_or(|last| last.ts <= record.ts) {
            self.held.push_back(record);
        } else {
            let at = self.held.partition_point(|held| held.ts <= record.ts);
            self.held.insert(at, record);
        }
    }

    /// Records held.
    pub fn len(&self) -> usize {
        self.held.len()
    }

    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// Passes on the records stamped before `mark`: every record stamped before it must have
    /// been held by now.
    pub fn release(&mut self, mark: u64) -> Vec<Record> {
        let count = self.held.partition_point(|held| held.ts < mark);
        self.pass_on(count)
    }

    /// Passes on the oldest records until at most `keep` are held, for when the reader has not
    /// been able to tell what is still on its way for too long.
    pub fn release_beyond(&mut self, keep: usize) -> Vec<Record> {
        self.pass_on(self.held.len().saturating_sub(keep))
    }

    /// Passes on every record held, then a lost record at `ts` if `dropped`, the program's
    /// count read at that time, says it dropped records after them.
    pub fn release_all(&mut self, ts: u64, dropped: u32) -> Vec<Record> {
        let mut out = self.pass_on(self.held.len());
        announce(&mut self.announced, ts, dropped, &mut out);
        out
    }

    /// Passes on the `count` oldest records, each after a lost record if its count of dropped
    /// records says the program dropped some since the last one passed on.
    fn pass_on(&mut self, count: usize) -> Vec<Record> {
        let mut out = Vec::with_capacity(count);
        for record in self.held.drain(..count) {
            announce(&mut self.announced, record.ts, record.dropped, &mut out);
            out.push(record);
        }
        out
    }
}

/// Adds a lost record at `ts` if `dropped` is ahead of the count already `announced`. The count
/// wraps, and records from different CPUs can carry it slightly out of order, so only a count
/// ahead of the last one tells of new losses.
fn announce(announced: &mut u32, ts: u64, dropped: u32, out: &mut Vec<Record>) {
    let new = dropped.wrapping_sub(*announced);
    if new.cast_signed() > 0 {
        out.push(Record {
            ts,
            dropped,
            event: Event::Lost {
                count: u64::from(new),
            },
        });
        *announced = dropped;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record told apart by its pid.
    fn exit(ts: u64, pid: i32, dropped: u32) -> Record {
        Record {
            ts,
            dropped,
            event: Event::Exit { pid },
        }
    }

    /// What `records` are, in order: a pid for an exit, the negated count for a loss.
    fn shown(records: &[Record]) -> Vec<(u64, i64)> {
        records
            .iter()
            .map(|record| match record.event {
                Event::Exit { pid } => (record.ts, i64::from(pid)),
                Event::Lost { count } => (record.ts, -i64::try_from(count).unwrap()),
                _ => panic!("{record:?}"),
            })
            .collect()
    }

    #[test]
    fn passes_on_what_is_before_the_mark_in_time_order() {
        let mut order = Order::default();
        for (ts, pid) in [(10, 1), (30, 2), (20, 3), (40, 4), (25, 5), (20, 6)] {
            order.hold(exit(ts, pid, 0));
        }
        // Records stamped alike keep the order they came in.
        assert_eq!(shown(&order.release(26)), [(10, 1), (20, 3), (20, 6), (25, 5)]);
        assert_eq!(order.len(), 2);
        assert!(
            order.release(30).is_empty(),
            "the mark itself is not before the mark"
        );
        // A record written very late still comes out, though after later ones.
        order.hold(exit(5, 7, 0));
        assert_eq!(shown(&order.release(100)), [(5, 7), (30, 2), (40, 4)]);
        assert!(order.is_empty());
    }

    #[test]
    fn marks_where_the_program_dropped_records() {
        let mut order = Order::default();
        for (ts, pid, dropped) in [(10, 1, 0), (30, 2, 3), (40, 3, 2), (50, 4, 3), (60, 5, 5)] {
            order.hold(exit(ts, pid, dropped));
        }
        // A count behind the last one came from a record made before those drops.
        assert_eq!(
            shown(&order.release(100)),
            [(10, 1), (30, -3), (30, 2), (40, 3), (50, 4), (60, -2), (60, 5)]
        );
    }

    #[test]
    fn the_count_of_dropped_records_wraps() {
        let mut order = Order::default();
        for (ts, pid, dropped) in [(10, 1, 0x7fff_ffff), (20, 2, 0xffff_fffe), (30, 3, 1)] {
            order.hold(exit(ts, pid, dropped));
        }
        assert_eq!(
            shown(&order.release(100)),
            [
                (10, -0x7fff_ffff),
                (10, 1),
                (20, -0x7fff_ffff),
                (20, 2),
                (30, -3),
                (30, 3)
            ]
        );
    }

    #[test]
    fn the_end_passes_on_everything_and_the_last_drops() {
        let mut order = Order::default();
        order.hold(exit(20, 2, 1));
        order.hold(exit(10, 1, 0));
        assert_eq!(
            shown(&order.release_all(99, 4)),
            [(10, 1), (20, -1), (20, 2), (99, -3)]
        );
        assert!(order.release_all(120, 4).is_empty(), "nothing new was dropped");
    }

    #[test]
    fn can_pass_on_the_oldest_to_keep_what_it_holds_bounded() {
        let mut order = Order::default();
        for ts in [50, 10, 40, 20, 30] {
            order.hold(exit(ts, i32::try_from(ts).unwrap(), 0));
        }
        assert_eq!(shown(&order.release_beyond(2)), [(10, 10), (20, 20), (30, 30)]);
        assert!(order.release_beyond(2).is_empty());
        assert_eq!(order.len(), 2);
    }
}
