/// The only reason this module exists is because `#[derive(NetworkBehavior)]` does not
/// namespace `Result` which pollutes the symbol table. The choice is to rename *our* result or to
/// put the behavior into a submodule.
use libp2p::{
    dcutr, identify, kad, ping, relay,
    swarm::{behaviour::toggle::Toggle, NetworkBehaviour},
    PeerId,
};

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "StampEvent")]
pub struct StampBehavior<S> {
    pub(crate) dcutr: Toggle<dcutr::Behaviour>,
    pub(crate) identify: identify::Behaviour,
    pub(crate) kad: kad::Behaviour<S>,
    pub(crate) ping: ping::Behaviour,
    pub(crate) relay_client: Toggle<relay::client::Behaviour>,
    pub(crate) relay: Toggle<relay::Behaviour>,
}

#[derive(Debug)]
pub enum StampEvent {
    Dcutr(dcutr::Event),
    Identify(identify::Event),
    Kad(kad::Event),
    PeerList(Vec<PeerId>),
    Ping(ping::Event),
    Relay(relay::Event),
    RelayClient(relay::client::Event),
}

impl From<dcutr::Event> for StampEvent {
    fn from(event: dcutr::Event) -> Self {
        Self::Dcutr(event)
    }
}

impl From<identify::Event> for StampEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(event)
    }
}

impl From<kad::Event> for StampEvent {
    fn from(event: kad::Event) -> Self {
        Self::Kad(event)
    }
}

impl From<ping::Event> for StampEvent {
    fn from(event: ping::Event) -> Self {
        Self::Ping(event)
    }
}

impl From<relay::Event> for StampEvent {
    fn from(event: relay::Event) -> Self {
        Self::Relay(event)
    }
}

impl From<relay::client::Event> for StampEvent {
    fn from(event: relay::client::Event) -> Self {
        Self::RelayClient(event)
    }
}
