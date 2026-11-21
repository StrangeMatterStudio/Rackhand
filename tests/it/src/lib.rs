//! Integration tier (design 14): hub, probes and helpers in Docker containers. Run with `cargo xtask ci it`.

#[cfg(test)]
mod callouts;
#[cfg(test)]
mod executor_it;
#[cfg(test)]
mod helper_it;
#[cfg(test)]
mod install_it;
#[cfg(test)]
mod jobs;
#[cfg(test)]
mod mirror_it;
#[cfg(test)]
mod probe_hub;
#[cfg(test)]
mod smoke;
#[cfg(test)]
mod ssh_it;
#[cfg(test)]
mod support;
#[cfg(test)]
mod wrapper;
