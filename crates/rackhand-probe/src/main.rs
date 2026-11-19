//! Composition root for the probe and its root helper (design 7.2).

mod helper;

fn main() {
    println!("rackhand-probe {}", env!("CARGO_PKG_VERSION"));
}
