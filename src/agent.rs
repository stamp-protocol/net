// NOTE: NResult is required because as of writing this, libp2p doesn't namespace the `Result`
// object in the swarm derive macro, so their Result conflicts with ours.
pub use crate::error::{Error, Result as NResult};
use futures::{prelude::*, select};
use libp2p::{
    Multiaddr, PeerId, Swarm,
    dcutr,
    identify,
    identity::{self, Keypair},
    kad,
    multiaddr,
    noise,
    ping,
    relay,
    request_response,
    swarm::{
        NetworkBehaviour, SwarmEvent,
        behaviour::toggle::Toggle,
    },
    tcp,
    yamux,
};
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{debug, error, info, warn, trace};

#[derive(Debug)]
pub enum Command {
    TopicSend { topic: String, message: Vec<u8> },
    TopicSubscribe { topic: String },
    TopicUnsubscribe { topic: String },
    Quit,
}

#[derive(Debug)]
pub enum Event {
    DiscoveryReady,
    Error(Error),
    GossipMessage { peer_id: Option<PeerId>, topic: String, data: Vec<u8> },
    GossipSubscribed { topic: String },
    GossipUnsubscribed { topic: String },
    Ping,
    Quit,
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "StampEvent")]
pub struct StampBehavior {
    dcutr: Toggle<dcutr::Behaviour>,
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    ping: ping::Behaviour,
    relay_client: Toggle<relay::client::Behaviour>,
    relay: Toggle<relay::Behaviour>,
}

#[derive(Debug)]
pub enum StampEvent {
    Dcutr(dcutr::Event),
    Gossipsub(gossipsub::Event),
    Identify(identify::Event),
    Kad(kad::Event),
    Ping(ping::Event),
    Relay(relay::Event),
    RelayClient(relay::client::Event),
}

impl From<dcutr::Event> for StampEvent {
    fn from(event: dcutr::Event) -> Self {
        Self::Dcutr(event)
    }
}

impl From<gossipsub::Event> for StampEvent {
    fn from(event: gossipsub::Event) -> Self {
        Self::Gossipsub(event)
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

/// Generate a new random peer key.
pub fn random_peer_key() -> Keypair {
    Keypair::generate_ed25519()
}

pub struct Agent {
    local_key: identity::Keypair,
    relay_mode: bool,
    swarm: Swarm<StampBehavior>,
}

impl Agent {
    /// Create a new agent.
    pub fn new(local_key: identity::Keypair, relay_mode: bool) -> NResult<Self> {
        let local_pubkey = local_key.public();
        let local_peer_id = PeerId::from(local_key.public());
        info!("Local peer id: {:?}", local_peer_id);

        let dcutr = {
            Toggle::from(if relay_mode { None } else { Some(dcutr::Behaviour::new(local_peer_id.clone())) })
        };

        let reqres = {

        };

        let identify = {
            let config = identify::Config::new("stampnet/1.0.0".into(), local_pubkey)
                .with_push_listen_addr_updates(false);
            identify::Behaviour::new(config)
        };

        let kad = {
            let store_config = kad::store::MemoryStoreConfig::default();
            let store = kad::store::MemoryStore::with_config(local_peer_id.clone(), store_config);
            let mut config = kad::Config::default();
            config.set_protocol_names(vec![libp2p::StreamProtocol::new("/stampnet/syncpub/1.0.0")]);
            config.set_record_filtering(kad::StoreInserts::Unfiltered);    // FilterBoth to enable filtering
            kad::Behaviour::with_config(local_peer_id.clone(), store, config)
        };

        let ping = {
            let config = ping::Config::new();
            ping::Behaviour::new(config)
        };

        let relay = {
            if public {
                info!("setup() -- creating relay behavior");
                let config = relay::Config::default();
                Toggle::from(Some(relay::Behaviour::new(local_peer_id.clone(), config)))
            } else {
                Toggle::from(None)
            }
        };

        let mut behavior = StampBehavior {
            dcutr,
            gossipsub,
            identify,
            kad,
            ping,
            relay,
            relay_client: Toggle::from(None),
        };

        let builder = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_dns()?;
        let swarm = if public {
            builder
                .with_behaviour(|_key| Ok(behavior))
                .map_err(|e| Error::BehaviorError(format!("{:?}", e)))?
                .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
                .build()
        } else {
            builder
                .with_relay_client(
                    noise::Config::new,
                    yamux::Config::default,
                )?
                .with_behaviour(|_key, relay_client| {
                    behavior.relay_client = Toggle::from(Some(relay_client));
                    Ok(behavior)
                })
                .map_err(|e| Error::BehaviorError(format!("{:?}", e)))?
                .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
                .build()
        };
        Ok(swarm)
    }
}

/// Create our listener/processer for the StampNet node.
#[tracing::instrument(skip(local_key), fields(%public))]
pub fn setup(local_key: identity::Keypair, public: bool) -> NResult<Swarm<StampBehavior>> {
}

/// Run our swarm and start talking to StampNet
#[tracing::instrument(skip(swarm, incoming, outgoing))]
pub async fn run(mut swarm: Swarm<StampBehavior>, mut incoming: Receiver<Command>, outgoing: Sender<Event>) -> NResult<()> {
    macro_rules! outgoing {
        ($val:expr) => {
            match outgoing.send($val).await {
                Err(e) => error!("stamp_net::core::run() -- {}:{} -- {:?}", file!(), line!(), e),
                _ => {}
            }
        }
    }
    let mut kad_has_bootstrapped = false;
    loop {
        select! {
            cmd = incoming.recv().fuse() => match cmd {
                Some(Command::TopicSend { topic: name, message }) => {
                    let topic = gossipsub::IdentTopic::new(name.as_str());
                    let len = message.len();
                    match swarm.behaviour_mut().gossipsub.publish(topic, message) {
                        Ok(msgid) => debug!("gossip: send: {} ({} -- {} bytes)", name, msgid, len),
                        Err(e) => info!("gossip: send: err: {:?}", e),
                    }
                }
                Some(Command::TopicSubscribe { topic: name }) => {
                    let topic = gossipsub::IdentTopic::new(name.as_str());
                    match swarm.behaviour_mut().gossipsub.subscribe(&topic) {
                        Ok(true) => info!("gossip: subscribe: {}", name),
                        Ok(false) => {}
                        Err(e) => warn!("gossip: subscribe: error: {:?}", e),
                    }

                    let key = kad::RecordKey::new(&name);
                    match swarm.behaviour_mut().kad.start_providing(key.clone()) {
                        Err(e) => {
                            outgoing!{ Event::Error(Error::KadRecord(e)) }
                        }
                        _ => {}
                    }
                    // we catch this on response and add providers
                    swarm.behaviour_mut().kad.get_providers(key);
                }
                Some(Command::TopicUnsubscribe { topic: name }) => {
                    let topic = gossipsub::IdentTopic::new(name.as_str());
                    match swarm.behaviour_mut().gossipsub.unsubscribe(&topic) {
                        Ok(true) => info!("gossip: unsubscribe: {}", name),
                        Ok(false) => {}
                        Err(e) => warn!("gossip: unsubscribe: error: {:?}", e),
                    }
                }
                Some(Command::Quit) => {
                    outgoing! { Event::Quit }
                    break;
                }
                _ => {}
            },
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(StampEvent::Identify(identify::Event::Received { peer_id, info })) => {
                    info!("identify: new peer: {} -- {:?} -- {:?}", peer_id, info.listen_addrs, info.protocols);
                    for addr in &info.listen_addrs {
                        swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                    }
                    if info.protocols.iter().find(|p| p.as_ref().contains("/libp2p/circuit/relay")).is_some() {
                        let mut seen: HashSet<Multiaddr> = HashSet::new();
                        for addr in info.listen_addrs.iter() {
                            let has_circuit = addr.iter().find(|m| matches!(m, multiaddr::Protocol::P2pCircuit)).is_some();
                            if has_circuit {
                                continue;
                            }
                            let has_p2p = addr.iter().find(|m| matches!(m, multiaddr::Protocol::P2p(_))).is_some();

                            let addr = addr.clone();
                            let addr = if !has_p2p {
                                addr.with(multiaddr::Protocol::P2p(info.public_key.to_peer_id().clone()))
                            } else {
                                addr
                            };
                            let circuit_addr = addr.with(multiaddr::Protocol::P2pCircuit);
                            if seen.contains(&circuit_addr) {
                                continue;
                            }
                            if swarm.listeners().find(|l| *l == &circuit_addr).is_some() {
                                continue;
                            }
                            info!("Creating circuit relay listener: {:?}", circuit_addr);
                            match swarm.listen_on(circuit_addr.clone()) {
                                Ok(_) => {}
                                Err(e) => {
                                    outgoing!{ Event::Error(Error::Transport(format!("{}", e))) }
                                }
                            }
                            seen.insert(circuit_addr);
                        }
                    }
                    if !kad_has_bootstrapped {
                        match swarm.behaviour_mut().kad.bootstrap() {
                            Err(_) => {
                                outgoing!{ Event::Error(Error::KadBootstrap) }
                            }
                            _ => {
                                kad_has_bootstrapped = true;
                            }
                        }
                    }
                }
                SwarmEvent::Behaviour(StampEvent::Gossipsub(gossipsub::Event::Message {message, ..})) => {
                    let gossipsub::Message { source, data, topic, .. } = message;
                    outgoing!{ Event::GossipMessage { peer_id: source, data, topic: topic.into_string() } }
                }
                SwarmEvent::Behaviour(StampEvent::Gossipsub(gossipsub::Event::Subscribed {topic, ..})) => {
                    outgoing!{ Event::GossipSubscribed { topic: topic.into_string() } }
                }
                SwarmEvent::Behaviour(StampEvent::Gossipsub(gossipsub::Event::Unsubscribed {topic, ..})) => {
                    outgoing!{ Event::GossipUnsubscribed { topic: topic.into_string() } }
                }
                SwarmEvent::Behaviour(StampEvent::Kad(kad::Event::OutboundQueryProgressed {id: _id, result: kad::QueryResult::Bootstrap(Ok(res)), step: _step, stats: _stats})) => {
                    if res.num_remaining == 0 {
                        info!("kad: bootstrapping complete");
                        outgoing!{ Event::DiscoveryReady }
                    }
                }
                SwarmEvent::Behaviour(StampEvent::Kad(kad::Event::OutboundQueryProgressed {id: _id, result: kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders { key, providers })), step: _step, stats: _stats})) => {
                    for provider in providers.iter() {
                        if provider == swarm.local_peer_id() {
                            continue;
                        }
                        info!("gossip: add peer from kad: {:?} -- {:?}", key, provider);
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&provider);
                        let addresses = swarm.connected_peers()
                            .map(|p| {
                                Multiaddr::empty()
                                    .with(multiaddr::Protocol::P2p(p.clone()))
                                    .with(multiaddr::Protocol::P2pCircuit)
                                    .with(multiaddr::Protocol::P2p(provider.clone()))
                            })
                            .collect::<Vec<_>>();
                        for addr in addresses {
                            info!("gossip: dialing {:?}", addr);
                            match swarm.dial(addr.clone()) {
                                Ok(_) => {}
                                Err(e) => {
                                    outgoing!{ Event::Error(Error::DialError(e)) }
                                }
                            }
                        }
                    }
                }
                SwarmEvent::Behaviour(StampEvent::Ping(ev)) => {
                    outgoing!{ Event::Ping }
                    trace!("ping: {:?}", ev);
                }
                SwarmEvent::Behaviour(any) => {
                    info!("swarm event: {:?}", any);
                }
                SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                    info!("swarm: connection opened: {} -- {:?}", peer_id, endpoint);
                }
                SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                    info!("swarm: connection closed: {} -- {:?}", peer_id, cause);
                    swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!("Listening on {:?}", address);
                }
                _ => {}
            },
        }
    }
    Ok(())
}


