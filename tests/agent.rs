mod common;

use futures::{join, select, FutureExt};
use stamp_core::{
    crypto::{
        base::{HashAlgo, SecretKey, SignKeypair},
        private::MaybePrivate,
    },
    dag::TransactionBody,
    identity::claim::ClaimSpec,
    util::Timestamp,
};
use stamp_net::{
    agent::{random_peer_key, Agent, Event, Quorum, TransactionQuery},
    error::Error,
    Multiaddr,
};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

#[tokio::test]
async fn starts_quits() {
    common::setup();
    let (agent1, mut ev1) = Agent::new(random_peer_key(), true).unwrap();
    let agent1_addr: Multiaddr = "/ip4/127.0.0.1/tcp/40010".parse().unwrap();
    let agent1 = Arc::new(agent1);

    let agent1_runner = agent1.run(agent1_addr.clone(), vec![]);

    tokio::task::spawn(async move {
        loop {
            let ev = ev1.recv().await.unwrap();
            match ev {
                Event::Quit => {
                    break;
                }
                _ => println!("ev: {:?}", ev),
            }
        }
    });

    let agent1_c = agent1.clone();
    tokio::task::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1000)).await;
        agent1_c.quit().await.unwrap();
    });

    let (runres,) = join!(agent1_runner);
    runres.unwrap();
}

#[tokio::test]
async fn bind_error() {
    common::setup();
    let (agent1, _ev1) = Agent::new(random_peer_key(), true).unwrap();
    let (agent2, _ev2) = Agent::new(random_peer_key(), true).unwrap();
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
async fn store_retrieve_identity_by_id() {
    common::setup();
    let (agent1, mut ev1) = Agent::new(random_peer_key(), true).unwrap();
    let (agent2, mut ev2) = Agent::new(random_peer_key(), true).unwrap();
    let (agent3, mut ev3) = Agent::new(random_peer_key(), true).unwrap();
    let agent1_addr: Multiaddr = "/ip4/127.0.0.1/tcp/40021".parse().unwrap();
    let agent2_addr: Multiaddr = "/ip4/127.0.0.1/tcp/40022".parse().unwrap();
    let agent3_addr: Multiaddr = "/ip4/127.0.0.1/tcp/40023".parse().unwrap();
    let agent1 = Arc::new(agent1);
    let agent2 = Arc::new(agent2);
    let agent3 = Arc::new(agent3);

    let agent1_runner = agent1.run(
        agent1_addr.clone(),
        vec![agent2_addr.clone(), agent3_addr.clone()],
    );
    let agent2_runner = agent2.run(
        agent2_addr.clone(),
        vec![agent1_addr.clone(), agent3_addr.clone()],
    );
    let agent3_runner = agent3.run(
        agent3_addr.clone(),
        vec![agent1_addr.clone(), agent2_addr.clone()],
    );

    let agent1_2 = agent1.clone();
    let agent2_2 = agent2.clone();
    let agent3_2 = agent3.clone();
    let id_task = tokio::task::spawn(async move {
        common::wait_on_event! { ev1, Event::KadBootstrapped }
        common::wait_on_event! { ev2, Event::KadBootstrapped }
        common::wait_on_event! { ev3, Event::KadBootstrapped }
        let (master_key, transactions, admin_key) = common::create_fake_identity_deterministic(
            Timestamp::from_str("2023-12-26T00:00:01Z").unwrap(),
            b"hi im butch",
        );
        let identity_id = transactions.identity_id().unwrap();
        let publish_trans = transactions
            .publish(&HashAlgo::Blake3, Timestamp::now())
            .unwrap()
            .sign(&master_key, &admin_key)
            .unwrap();
        let pubres = agent1_2
            .publish_identity(publish_trans.clone(), Quorum::One)
            .await
            .unwrap();
        assert_eq!(
            pubres,
            "/stampnet/publish/identity/37eTM628v-V3OxM7YFwaui64LoX84QkhoaYpqtugXqMA"
        );

        tokio::time::sleep(Duration::from_millis(1000)).await;

        let found1 = agent1_2
            .lookup_identity(identity_id.clone())
            .await
            .unwrap()
            .expect("actual identity");
        found1.verify_hash_and_signatures().unwrap();
        assert_eq!(found1.id(), publish_trans.id());

        let found2 = agent2_2
            .lookup_identity(identity_id.clone())
            .await
            .unwrap()
            .expect("actual identity");
        found2.verify_hash_and_signatures().unwrap();
        assert_eq!(found2.id(), publish_trans.id());

        let found3 = agent3_2
            .lookup_identity(identity_id.clone())
            .await
            .unwrap()
            .expect("actual identity");
        found3.verify_hash_and_signatures().unwrap();
        assert_eq!(found3.id(), publish_trans.id());

        agent1_2.quit().await.unwrap();
        agent2_2.quit().await.unwrap();
        agent3_2.quit().await.unwrap();
    });

    let (_, runres1, runres2, runres3) =
        join!(id_task, agent1_runner, agent2_runner, agent3_runner);
    runres1.unwrap();
    runres2.unwrap();
    runres3.unwrap();
}

#[tokio::test]
async fn identity_store_failures() {
    common::setup();
    // TODO: why does turning off relay mode break protocol negotiation??
    let (agent1, mut ev1) = Agent::new(random_peer_key(), false).unwrap();
    let (agent2, mut ev2) = Agent::new(random_peer_key(), false).unwrap();
    let (agent3, mut ev3) = Agent::new(random_peer_key(), false).unwrap();
    let agent1_addr: Multiaddr = "/ip4/127.0.0.1/tcp/40041".parse().unwrap();
    let agent2_addr: Multiaddr = "/ip4/127.0.0.1/tcp/40042".parse().unwrap();
    let agent3_addr: Multiaddr = "/ip4/127.0.0.1/tcp/40043".parse().unwrap();
    let agent1 = Arc::new(agent1);
    let agent2 = Arc::new(agent2);
    let agent3 = Arc::new(agent3);

    let agent1_runner = agent1.run(
        agent1_addr.clone(),
        vec![agent2_addr.clone(), agent3_addr.clone()],
    );
    let agent2_runner = agent2.run(
        agent2_addr.clone(),
        vec![agent1_addr.clone(), agent3_addr.clone()],
    );
    let agent3_runner = agent3.run(
        agent3_addr.clone(),
        vec![agent1_addr.clone(), agent2_addr.clone()],
    );

    let agent1_2 = agent1.clone();
    let agent2_2 = agent2.clone();
    let agent3_2 = agent3.clone();
    let id_task = tokio::task::spawn(async move {
        common::wait_on_event! { ev1, Event::KadBootstrapped }
        common::wait_on_event! { ev2, Event::KadBootstrapped }
        common::wait_on_event! { ev3, Event::KadBootstrapped }
        let now = Timestamp::from_str("2023-12-26T00:00:01Z").unwrap();
        let (master_key, transactions, admin_key) =
            common::create_fake_identity_deterministic(now.clone(), b"hi im butch");
        let name = String::from_iter(&['j'; 1024 * 1024 * 8]);
        let claim = transactions
            .make_claim(
                &HashAlgo::Blake3,
                now.clone(),
                ClaimSpec::Name(MaybePrivate::new_public(name)),
                Some("my name"),
            )
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
        let pubres = agent1_2
            .publish_identity(publish_trans.clone(), Quorum::One)
            .await;
        assert!(matches!(pubres, Err(Error::KadPutQuorumFailed)));

        tokio::time::sleep(Duration::from_millis(1000)).await;

        let found1 = agent1_2
            .lookup_identity(identity_id.clone())
            .await
            .unwrap()
            .expect("actual identity");
        found1.verify_hash_and_signatures().unwrap();
        assert_eq!(found1.id(), publish_trans.id());

        let found2 = agent2_2
            .lookup_identity(identity_id.clone())
            .await
            .unwrap()
            .expect("actual identity");
        found2.verify_hash_and_signatures().unwrap();
        assert_eq!(found2.id(), publish_trans.id());

        let found3 = agent3_2
            .lookup_identity(identity_id.clone())
            .await
            .unwrap()
            .expect("actual identity");
        found3.verify_hash_and_signatures().unwrap();
        assert_eq!(found3.id(), publish_trans.id());

        agent1_2.quit().await.unwrap();
        agent2_2.quit().await.unwrap();
        agent3_2.quit().await.unwrap();
    });

    let (_, runres1, runres2, runres3) =
        join!(id_task, agent1_runner, agent2_runner, agent3_runner);
    runres1.unwrap();
    runres2.unwrap();
    runres3.unwrap();
}

#[tokio::test]
async fn topic_join_req_res() {
    common::setup();

    let (_, secret_key1, sign_key1) = common::create_sync_keys(b"SELLING BEAN BAGS");
    let (_, secret_key2, sign_key2) = common::create_sync_keys(b"SELLING BEAN BAGS");

    let (agent1, ev1) = Agent::new(random_peer_key(), true).unwrap();
    let (agent2, ev2) = Agent::new(random_peer_key(), true).unwrap();
    let agent1 = Arc::new(agent1);
    let agent2 = Arc::new(agent2);
    let agent1_addr: Multiaddr = "/ip4/127.0.0.1/tcp/40031".parse().unwrap();
    let agent2_addr: Multiaddr = "/ip4/127.0.0.1/tcp/40032".parse().unwrap();

    let agent1_runner = agent1.run(agent1_addr.clone(), vec![agent2_addr.clone()]);
    let agent2_runner = agent2.run(agent2_addr.clone(), vec![agent1_addr.clone()]);

    async fn topic_agent(
        name: &str,
        agent: Arc<Agent>,
        mut ev: tokio::sync::mpsc::Receiver<Event>,
        secret_key: &SecretKey,
        sign_key: SignKeypair,
        messages: Vec<Vec<u8>>,
    ) -> Vec<Vec<u8>> {
        let name1 = String::from(name);
        let ev_handle = tokio::task::spawn(async move {
            loop {
                match ev.recv().await {
                    Some(Event::Quit) => break,
                    Some(ev) => {
                        debug!("{}: event: {:?}", name1, ev);
                    }
                    None => {}
                }
            }
        });
        agent
            .join_topic(&sign_key.clone().into(), "beanie-baby-chat")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(1000)).await;
        let recv = agent
            .query_topic(
                secret_key,
                &sign_key,
                "beanie-baby-chat",
                TransactionQuery::All,
            )
            .await
            .unwrap()
            .expect("has actual results")
            .into_iter()
            .map(|x| match x.entry().body() {
                TransactionBody::ExtV1 { payload, .. } => {
                    vec![]
                }
                _ => panic!("bad transaction: {:?}", x),
            })
            .collect::<Vec<_>>();
        tokio::time::sleep(Duration::from_millis(1000)).await;
        agent.quit().await.unwrap();
        ev_handle.await.unwrap();
        recv
    }

    let agent1_2 = agent1.clone();
    tokio::task::spawn(async move {
        let recv = topic_agent(
            "butch",
            agent1_2,
            ev1,
            &secret_key1,
            sign_key1,
            vec![
                Vec::from(b"chicken and beans"),
                Vec::from(b"bruchetta nights"),
            ],
        )
        .await;
        assert_eq!(
            recv,
            vec![Vec::from(b"sha na na"), Vec::from(b"get a job"),]
        );
    });

    let agent2_2 = agent2.clone();
    tokio::task::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let recv = topic_agent(
            "dotty",
            agent2_2,
            ev2,
            &secret_key2,
            sign_key2,
            vec![Vec::from(b"sha na na"), Vec::from(b"get a job")],
        )
        .await;
        assert_eq!(
            recv,
            vec![
                Vec::from(b"chicken and beans"),
                Vec::from(b"bruchetta nights"),
            ]
        );
    });

    let (res1, res2) = join!(agent1_runner, agent2_runner);
    res1.unwrap();
    res2.unwrap();
}
