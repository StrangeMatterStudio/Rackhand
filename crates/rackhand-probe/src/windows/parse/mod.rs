//! Platform-neutral parsing of what the Windows collectors read (T89): tested everywhere, on recorded outputs.

pub mod conntable;
pub mod logon;
pub mod pipe;
pub mod procs;
pub mod wmi;

#[cfg(test)]
mod windows_parse;
