//! Append-only buffer segments (7.4.1): 4 MB files, at most 64 MB in total and 24 hours of reports. The oldest data
//! goes first, and every unsent report that is dropped is recorded as a range for `DataDropped` (7.3.2, E2).

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub segment_bytes: u64,
    pub max_bytes: u64,
    pub max_age_ms: i64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { segment_bytes: 4 * 1024 * 1024, max_bytes: 64 * 1024 * 1024, max_age_ms: 24 * 3600 * 1000 }
    }
}

/// Reports deleted unsent: one `DataDropped` each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dropped {
    pub epoch: u64,
    pub from_seq: u64,
    pub to_seq: u64,
}

#[derive(Debug, Clone)]
pub struct Record {
    pub epoch: u64,
    pub seq: u64,
    pub sampled_at_ms: i64,
    offset: u64,
    len: u32,
    gone: bool,
}

/// Where a pending report is stored, so replay can read it beside live sends without holding the buffer. A report
/// acked or dropped meanwhile may be gone (its segment deleted): reading it then fails, and replay skips it.
#[derive(Debug, Clone)]
pub struct Stored {
    pub epoch: u64,
    pub seq: u64,
    path: PathBuf,
    offset: u64,
    len: u32,
}

impl Stored {
    pub fn read(&self) -> Result<Vec<u8>, BufferError> {
        let mut f = File::open(&self.path)?;
        f.seek(SeekFrom::Start(self.offset))?;
        let mut buf = vec![0u8; self.len as usize];
        f.read_exact(&mut buf)?;
        Ok(buf)
    }
}

#[derive(Debug)]
struct Segment {
    path: PathBuf,
    bytes: u64,
    records: Vec<Record>,
}

#[derive(Debug, thiserror::Error)]
pub enum BufferError {
    #[error("report {1} of epoch {0} is not in the buffer")]
    Missing(u64, u64),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

const HEADER: u64 = 4 + 8 + 8 + 8;

#[derive(Debug)]
pub struct Buffer {
    dir: PathBuf,
    limits: Limits,
    segments: Vec<Segment>,
    next_segment: u64,
    dropped: Vec<Dropped>,
}

impl Buffer {
    pub fn open(dir: &Path, limits: Limits, now_ms: i64) -> Result<Buffer, BufferError> {
        std::fs::create_dir_all(dir)?;
        let mut names: Vec<(u64, PathBuf)> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter_map(|p| {
                let n = p.file_name()?.to_str()?.strip_prefix("seg-")?.strip_suffix(".bin")?.parse().ok()?;
                Some((n, p))
            })
            .collect();
        names.sort();
        let next_segment = names.last().map(|(n, _)| n + 1).unwrap_or(0);
        let mut segments = Vec::new();
        for (_, path) in names {
            segments.push(read_segment(&path)?);
        }
        let mut buffer = Buffer { dir: dir.to_path_buf(), limits, segments, next_segment, dropped: Vec::new() };
        buffer.expire(now_ms)?;
        Ok(buffer)
    }

    pub fn append(
        &mut self,
        epoch: u64,
        seq: u64,
        sampled_at_ms: i64,
        payload: &[u8],
        now_ms: i64,
    ) -> Result<(), BufferError> {
        let size = HEADER + payload.len() as u64;
        let need_new = self.segments.last().is_none_or(|s| s.bytes + size > self.limits.segment_bytes && s.bytes > 0);
        if need_new {
            let path = self.dir.join(format!("seg-{:016}.bin", self.next_segment));
            self.next_segment += 1;
            File::create(&path)?;
            self.segments.push(Segment { path, bytes: 0, records: Vec::new() });
        }
        let seg = self.segments.last_mut().ok_or_else(|| std::io::Error::other("no segment"))?;
        let mut file = OpenOptions::new().append(true).open(&seg.path)?;
        let mut rec = Vec::with_capacity(size as usize);
        rec.extend_from_slice(&((size - 4) as u32).to_be_bytes());
        rec.extend_from_slice(&epoch.to_be_bytes());
        rec.extend_from_slice(&seq.to_be_bytes());
        rec.extend_from_slice(&sampled_at_ms.to_be_bytes());
        rec.extend_from_slice(payload);
        file.write_all(&rec)?;
        file.sync_data()?;
        seg.records.push(Record {
            epoch,
            seq,
            sampled_at_ms,
            offset: seg.bytes + HEADER,
            len: payload.len() as u32,
            gone: false,
        });
        seg.bytes += size;
        self.enforce_size()?;
        self.expire(now_ms)
    }

    /// Unacked reports, oldest first.
    pub fn pending(&self) -> impl Iterator<Item = &Record> {
        self.segments.iter().flat_map(|s| s.records.iter()).filter(|r| !r.gone)
    }

    /// The pending reports sampled before `before_ms`, oldest first.
    pub fn stored_before(&self, before_ms: i64) -> Vec<Stored> {
        self.segments
            .iter()
            .flat_map(|s| s.records.iter().map(move |r| (s, r)))
            .filter(|(_, r)| !r.gone && r.sampled_at_ms < before_ms)
            .map(|(s, r)| Stored { epoch: r.epoch, seq: r.seq, path: s.path.clone(), offset: r.offset, len: r.len })
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.pending().next().is_none()
    }

    pub fn read(&self, epoch: u64, seq: u64) -> Result<Vec<u8>, BufferError> {
        for seg in &self.segments {
            if let Some(r) = seg.records.iter().find(|r| r.epoch == epoch && r.seq == seq && !r.gone) {
                let mut f = File::open(&seg.path)?;
                f.seek(SeekFrom::Start(r.offset))?;
                let mut buf = vec![0u8; r.len as usize];
                f.read_exact(&mut buf)?;
                return Ok(buf);
            }
        }
        Err(BufferError::Missing(epoch, seq))
    }

    /// Deletes the reports inside the acked ranges (inclusive), and only those.
    pub fn ack(&mut self, epoch: u64, ranges: &[(u64, u64)]) -> Result<(), BufferError> {
        for seg in &mut self.segments {
            for r in &mut seg.records {
                if r.epoch == epoch && ranges.iter().any(|&(from, to)| r.seq >= from && r.seq <= to) {
                    r.gone = true;
                }
            }
        }
        self.remove_empty_segments()
    }

    /// Drops reports older than the age limit, recording them as dropped.
    pub fn expire(&mut self, now_ms: i64) -> Result<(), BufferError> {
        let cutoff = now_ms - self.limits.max_age_ms;
        let mut dropped = Vec::new();
        for seg in &mut self.segments {
            for r in &mut seg.records {
                if !r.gone && r.sampled_at_ms < cutoff {
                    r.gone = true;
                    dropped.push((r.epoch, r.seq));
                }
            }
        }
        for (epoch, seq) in dropped {
            self.record_dropped(epoch, seq);
        }
        self.remove_empty_segments()
    }

    pub fn total_bytes(&self) -> u64 {
        self.segments.iter().map(|s| s.bytes).sum()
    }

    /// The dropped ranges since the last call, merged.
    pub fn take_dropped(&mut self) -> Vec<Dropped> {
        std::mem::take(&mut self.dropped)
    }

    fn record_dropped(&mut self, epoch: u64, seq: u64) {
        if let Some(last) = self.dropped.last_mut() {
            if last.epoch == epoch && last.to_seq + 1 == seq {
                last.to_seq = seq;
                return;
            }
        }
        self.dropped.push(Dropped { epoch, from_seq: seq, to_seq: seq });
    }

    fn enforce_size(&mut self) -> Result<(), BufferError> {
        while self.total_bytes() > self.limits.max_bytes && self.segments.len() > 1 {
            let seg = self.segments.remove(0);
            for r in seg.records.iter().filter(|r| !r.gone) {
                self.record_dropped(r.epoch, r.seq);
            }
            std::fs::remove_file(&seg.path)?;
        }
        Ok(())
    }

    fn remove_empty_segments(&mut self) -> Result<(), BufferError> {
        let last = self.segments.len().saturating_sub(1);
        let mut keep = Vec::new();
        for (i, seg) in std::mem::take(&mut self.segments).into_iter().enumerate() {
            if i != last && seg.records.iter().all(|r| r.gone) {
                std::fs::remove_file(&seg.path)?;
            } else {
                keep.push(seg);
            }
        }
        self.segments = keep;
        Ok(())
    }
}

/// Reads a segment's records, ignoring a partly written record at the end (a crash mid-write).
fn read_segment(path: &Path) -> Result<Segment, BufferError> {
    let data = std::fs::read(path)?;
    let mut records = Vec::new();
    let mut pos = 0u64;
    while pos + HEADER <= data.len() as u64 {
        let p = pos as usize;
        let rest = u32::from_be_bytes(data[p..p + 4].try_into().unwrap_or([0; 4])) as u64;
        if pos + 4 + rest > data.len() as u64 || rest < HEADER - 4 {
            break;
        }
        let u = |o: usize| u64::from_be_bytes(data[p + o..p + o + 8].try_into().unwrap_or([0; 8]));
        records.push(Record {
            epoch: u(4),
            seq: u(12),
            sampled_at_ms: u(20) as i64,
            offset: pos + HEADER,
            len: (rest - (HEADER - 4)) as u32,
            gone: false,
        });
        pos += 4 + rest;
    }
    Ok(Segment { path: path.to_path_buf(), bytes: pos, records })
}
