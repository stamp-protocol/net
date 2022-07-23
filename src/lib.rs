//! StampNet is the system responsible for the storage and retrieval of published
//! identities. It also provides mechanisms for syncing private identity data
//! securely between select peers/devices.

pub mod error;
pub mod core;
pub mod sync;
mod util;

pub use crate::core::{Command, Event, setup, random_peer_key};
pub use crate::error::Error;
pub use libp2p::multiaddr::{Multiaddr, Protocol};

