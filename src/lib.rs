//! # mine-rs
//!
//! A project aimed towards providing tools necessary to implement Clients and
//! Servers for Minecraft.
#[cfg(feature = "net")]
pub use miners_net as net;
#[cfg(feature = "packets")]
pub use miners_packets as packets;
