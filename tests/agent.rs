mod common;

use futures::{future::join_all, join};
use stamp_core::{
    crypto::{base::HashAlgo, private::MaybePrivate},
    identity::claim::ClaimSpec,
    util::Timestamp,
};
use stamp_net::{
    agent::{DHTMode, Quorum, RelayMode},
    error::Error,
    Multiaddr,
};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn starts_quits() {
    common::setup();
    let nodes = common::spawn_nodes(1, |i| format!("/ip4/127.0.0.1/tcp/{}", i + 3000), RelayMode::None, DHTMode::Server);
    let runners = nodes.iter().map(|x| x.agent.run(x.multiaddr.clone(), vec![])).collect::<Vec<_>>();
    let evlisteners = nodes.iter().map(|node| common::node_event_sink(node)).collect::<Vec<_>>();
    let nodes2 = nodes.clone();
    let id_task = tokio::task::spawn(async move {
        common::connect_nodes(&nodes2).await;
        common::wait_for_node_connections(&nodes2, 2).await;
        common::bootstrap_dht(&nodes2).await;

        for node in nodes2.iter() {
            node.agent.quit().await.unwrap();
        }
    });

    let (_, runres, _) = join!(id_task, join_all(runners), join_all(evlisteners));
    for res in runres {
        res.unwrap();
    }
}

#[tokio::test]
async fn bind_error() {
    common::setup();
    let (agent1, _ev1) = common::agent(RelayMode::None, DHTMode::Client);
    let (agent2, _ev2) = common::agent(RelayMode::None, DHTMode::Client);
    // purposefully give them the same binding
    let agent1_addr: Multiaddr = "/ip4/127.0.0.1/tcp/40019".parse().unwrap();
    let agent2_addr: Multiaddr = "/ip4/127.0.0.1/tcp/40019".parse().unwrap();
    let agent1 = Arc::new(agent1);
    let agent2 = Arc::new(agent2);

    let agent1_runner = agent1.run(agent1_addr.clone(), vec![agent2_addr.clone()]);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let agent2_runner = agent2.run(agent2_addr.clone(), vec![agent1_addr.clone()]);

    let agent1_2 = agent1.clone();
    tokio::task::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1000)).await;
        agent1_2.quit().await.unwrap();
    });

    agent1_runner.await.unwrap();
    match agent2_runner.await {
        Ok(_) => panic!("should have errored"),
        Err(e) => assert!(matches!(e, Error::Transport(_))),
    }
}

#[tokio::test]
async fn store_retrieve_identity() {
    common::setup();
    let nodes = common::spawn_nodes(32, |i| format!("/ip4/127.0.0.1/tcp/{}", i + 40040), RelayMode::None, DHTMode::Server);
    let runners = nodes.iter().map(|x| x.agent.run(x.multiaddr.clone(), vec![])).collect::<Vec<_>>();
    let evlisteners = nodes.iter().map(|node| common::node_event_sink(node)).collect::<Vec<_>>();
    let nodes2 = nodes.clone();
    let id_task = tokio::task::spawn(async move {
        common::connect_nodes(&nodes2).await;
        common::wait_for_node_connections(&nodes2, 2).await;
        common::bootstrap_dht(&nodes2).await;

        // publish an identity
        let now = Timestamp::from_str("2023-12-26T00:00:01Z").unwrap();
        let (master_key, transactions, admin_key) = common::create_fake_identity_deterministic(now.clone(), b"hi im butch");
        let identity_id = transactions.identity_id().unwrap();
        let publish_trans = transactions
            .publish(&HashAlgo::Blake3, Timestamp::now())
            .unwrap()
            .sign(&master_key, &admin_key)
            .unwrap();
        nodes2[0]
            .agent
            .publish_identity(publish_trans.clone(), Quorum::Majority)
            .await
            .unwrap();

        // everyone fights, no one quits. except node[0]
        nodes2[0].agent.quit().await.unwrap();

        // look up our identity now that the publishing node is ...indisposed
        for node in nodes2.iter().skip(1) {
            let found = node
                .agent
                .lookup_identity(identity_id.clone())
                .await
                .unwrap()
                .expect("actual identity");
            found.verify_hash_and_signatures().unwrap();
            assert_eq!(found.id(), publish_trans.id());
        }

        for node in nodes2.iter().skip(1) {
            node.agent.quit().await.unwrap();
        }
    });

    let (_, runres, _) = join!(id_task, join_all(runners), join_all(evlisteners));
    for res in runres {
        res.unwrap();
    }
}

#[tokio::test]
async fn identity_too_large_store_locally() {
    common::setup();
    let nodes = common::spawn_nodes(32, |i| format!("/ip4/127.0.0.1/tcp/{}", i + 50040), RelayMode::None, DHTMode::Server);
    let runners = nodes.iter().map(|x| x.agent.run(x.multiaddr.clone(), vec![])).collect::<Vec<_>>();
    let evlisteners = nodes.iter().map(|node| common::node_event_sink(node)).collect::<Vec<_>>();
    let nodes2 = nodes.clone();
    let id_task = tokio::task::spawn(async move {
        common::connect_nodes(&nodes2).await;
        common::wait_for_node_connections(&nodes2, 2).await;
        common::bootstrap_dht(&nodes2).await;

        // publish an outlandishly large identity.
        let now = Timestamp::from_str("2023-12-26T00:00:01Z").unwrap();
        let (master_key, transactions, admin_key) = common::create_fake_identity_deterministic(now.clone(), b"hi im butch");
        let name = String::from_iter(vec!['j'; 1024 * 1024 * 8]); // wow. that's a big one.
        let claim = transactions
            .make_claim(&HashAlgo::Blake3, now.clone(), ClaimSpec::Name(MaybePrivate::new_public(name)), None::<String>)
            .unwrap()
            .sign(&master_key, &admin_key)
            .unwrap();
        let transactions = transactions.push_transaction(claim).unwrap();
        let identity_id = transactions.identity_id().unwrap();
        let publish_trans = transactions
            .publish(&HashAlgo::Blake3, Timestamp::now())
            .unwrap()
            .sign(&master_key, &admin_key)
            .unwrap();

        let publish_res = nodes2[0]
            .agent
            .publish_identity(publish_trans.clone(), Quorum::N(std::num::NonZeroUsize::new(3).unwrap()))
            .await;
        assert!(matches!(publish_res, Err(Error::IdentityTooLarge)));

        for node in nodes2.iter() {
            let not_found = node.agent.lookup_identity(identity_id.clone()).await;
            assert!(matches!(not_found, Err(Error::DHTLookupFailed { .. })));
        }

        for node in nodes2.iter() {
            node.agent.quit().await.unwrap();
        }
    });

    let (_, runres, _) = join!(id_task, join_all(runners), join_all(evlisteners));
    for res in runres {
        res.unwrap();
    }
}
