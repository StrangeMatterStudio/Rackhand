use std::collections::BTreeMap;
use std::io::Read;

use crate::series::chunk::{Tier, closes_before};
use crate::series::codec::{Chunk, Coder, Column, decode, encode};
use crate::series::step::Step;

/// A small deterministic generator, so a failing case can be replayed from its seed.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn random_ts(rng: &mut Rng, n: usize) -> Vec<i64> {
    let mut t = rng.next() as i64 >> 20;
    (0..n)
        .map(|_| {
            t += match rng.below(4) {
                0 => 15_000,
                1 => rng.below(40_000) as i64,
                2 => rng.below(1 << 40) as i64,
                _ => 0,
            };
            t
        })
        .collect()
}

fn random_ints(rng: &mut Rng, n: usize) -> Vec<i64> {
    let mut v = rng.next() as i64;
    (0..n)
        .map(|_| {
            v = match rng.below(5) {
                0 => v,
                1 => v.wrapping_add(rng.below(100) as i64 - 50),
                2 => v.wrapping_add(rng.below(1 << 30) as i64 - (1 << 29)),
                3 => rng.next() as i64,
                _ => [i64::MIN, i64::MAX, 0, -1][rng.below(4) as usize],
            };
            v
        })
        .collect()
}

fn random_floats(rng: &mut Rng, n: usize) -> Vec<f64> {
    let mut v = 1.5;
    (0..n)
        .map(|_| {
            v = match rng.below(6) {
                0 => v,
                1 => v + (rng.below(1000) as f64 - 500.0) / 7.0,
                2 => f64::from_bits(rng.next()),
                3 => [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.0, 0.0][rng.below(5) as usize],
                4 => f64::from_bits(0x7FF8_0000_0000_0001 | (rng.next() & 0xF_FFFF)),
                _ => rng.below(1 << 50) as f64 * 0.01,
            };
            v
        })
        .collect()
}

#[test]
fn round_trip_is_lossless() {
    let steps = [Step::One, Step::Hundredths, Step::Tenths, Step::KiB];
    for case in 0..10_000u64 {
        let mut rng = Rng::new(case);
        let n = 1 + rng.below(130) as usize;
        let ncols = 1 + rng.below(3) as usize;
        let cols = (0..ncols)
            .map(|_| {
                if rng.below(2) == 0 {
                    Column::Int { step: steps[rng.below(4) as usize], values: random_ints(&mut rng, n) }
                } else {
                    Column::Float(random_floats(&mut rng, n))
                }
            })
            .collect();
        let chunk = Chunk { ts: random_ts(&mut rng, n), cols };
        let back = decode(&encode(&chunk)).unwrap_or_else(|e| panic!("case {case}: {e}"));
        assert_eq!(back.ts, chunk.ts, "case {case}: timestamps");
        assert_eq!(back.cols.len(), chunk.cols.len(), "case {case}: columns");
        for (a, b) in back.cols.iter().zip(&chunk.cols) {
            match (a, b) {
                (Column::Int { step: sa, values: va }, Column::Int { step: sb, values: vb }) => {
                    assert_eq!((sa, va), (sb, vb), "case {case}: integer column");
                }
                (Column::Float(va), Column::Float(vb)) => {
                    let bits = |v: &Vec<f64>| v.iter().map(|x| x.to_bits()).collect::<Vec<_>>();
                    assert_eq!(bits(va), bits(vb), "case {case}: float column");
                }
                _ => panic!("case {case}: column kind changed"),
            }
        }
    }
}

#[test]
fn cheapest_coder_is_chosen_per_column() {
    let ts: Vec<i64> = (0..120).map(|i| i * 15_000).collect();
    let constant = vec![4_200i64; 120];
    // a random walk: small steps, so delta coding wins
    let mut rng = Rng::new(7);
    let mut v = 1_000_000i64;
    let walk: Vec<i64> = (0..120)
        .map(|_| {
            v += rng.below(200) as i64 - 100;
            v
        })
        .collect();
    // a counter rising steadily with a little noise: delta-of-delta wins
    let counter: Vec<i64> = (0..120).map(|i| 10_000_000 + i * 5_000 + (i % 3)).collect();
    let mut seen = Vec::new();
    for values in [constant, walk, counter] {
        let chunk = Chunk { ts: ts.clone(), cols: vec![Column::Int { step: Step::One, values: values.clone() }] };
        let chosen = crate::series::codec::coder_for(&values);
        let size = encode(&chunk).len();
        for other in [Coder::DeltaOfDelta, Coder::Delta, Coder::Xor] {
            let forced = crate::series::codec::encode_with(&chunk, &[other]);
            assert!(size <= forced.len(), "{chosen:?} chosen but {other:?} is smaller");
        }
        seen.push(chosen);
    }
    assert_eq!(seen[1], Coder::Delta, "random walk");
    assert_eq!(seen[2], Coder::DeltaOfDelta, "steady counter");
}

/// The 7.4.2 unit of each metric in the recorded sample.
fn catalogue_unit(name: &str) -> &'static str {
    if name.ends_with("_pct") {
        "%"
    } else if name.starts_with("load.") {
        "ratio"
    } else if name.ends_with("_bytes") {
        "bytes"
    } else if name.ends_with("_bps") {
        "B/s"
    } else if name.ends_with("_iops") {
        "ops/s"
    } else if name.ends_with("_pps") {
        "pkts/s"
    } else if name == "uptime_s" {
        "s"
    } else {
        "count"
    }
}

fn chunked_bytes(tier: Tier, step: Option<Step>, ts: &[i64], cols: &[Vec<f64>]) -> (usize, usize) {
    let (mut bytes, mut values) = (0, 0);
    let mut start = 0;
    for i in 1..=ts.len() {
        if i == ts.len() || closes_before(tier, ts[start], i - start, ts[i]) {
            let chunk = Chunk {
                ts: ts[start..i].to_vec(),
                cols: cols.iter().map(|c| Column::from_values(step, &c[start..i])).collect(),
            };
            bytes += encode(&chunk).len();
            values += (i - start) * cols.len();
            start = i;
        }
    }
    (bytes, values)
}

#[test]
fn bytes_per_value_on_recorded_data_within_spike_result() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/s8-sample.csv.zst");
    let mut text = String::new();
    zstd::Decoder::new(std::fs::File::open(path).unwrap()).unwrap().read_to_string(&mut text).unwrap();
    let mut series: BTreeMap<&str, Vec<f64>> = BTreeMap::new();
    for line in text.lines() {
        let mut p = line.splitn(3, ',');
        let (_, key, value) = (p.next().unwrap(), p.next().unwrap(), p.next().unwrap());
        series.entry(key).or_default().push(value.parse().unwrap());
    }
    let (mut b0, mut n0, mut b1, mut n1) = (0, 0, 0, 0);
    for (key, values) in &series {
        let name = key.split('{').next().unwrap();
        let step = Step::for_metric(name, catalogue_unit(name));
        assert!(step.is_some(), "{name} has a step");
        // the sample as a probe stamps it: one scheduled 15 s tick after another (T05 recorded at read time)
        let first = 1_795_069_665_000i64;
        let ts: Vec<i64> = (0..values.len() as i64).map(|i| first + i * 15_000).collect();
        let (b, n) = chunked_bytes(Tier::Raw, step, &ts, std::slice::from_ref(values));
        (b0, n0) = (b0 + b, n0 + n);
        // tier 1: min, max and avg over each minute
        let (mut mt, mut cols) = (Vec::new(), vec![Vec::new(), Vec::new(), Vec::new()]);
        for (t, w) in ts.chunks(4).zip(values.chunks(4)) {
            mt.push(t[0]);
            cols[0].push(w.iter().copied().fold(f64::MAX, f64::min));
            cols[1].push(w.iter().copied().fold(f64::MIN, f64::max));
            cols[2].push(w.iter().sum::<f64>() / w.len() as f64);
        }
        let (b, n) = chunked_bytes(Tier::Minute, step, &mt, &cols);
        (b1, n1) = (b1 + b, n1 + n);
    }
    let (bpv0, bpv1) = (b0 as f64 / n0 as f64, b1 as f64 / n1 as f64);
    eprintln!("tier 0 {bpv0:.3}, tier 1 {bpv1:.3} bytes per value");
    // spike S8 on the same sample: 1.04 (tier 0) and 0.96 (tier 1, 120-point chunks) bytes per value
    assert!((bpv0 - 1.04).abs() <= 0.104, "tier 0: {bpv0:.3} bytes per value");
    assert!((bpv1 - 0.96).abs() <= 0.096, "tier 1: {bpv1:.3} bytes per value");
}
