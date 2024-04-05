//! StampNet is the system responsible for the storage and retrieval of published
//! identities. It also provides mechanisms for syncing private identity data
//! securely between select peers/devices.

pub mod agent;
pub mod error;

pub use crate::error::Error;
pub use libp2p::multiaddr::{Multiaddr, Protocol};
