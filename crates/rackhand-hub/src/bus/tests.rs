use std::time::{Duration, Instant};

use super::{Bus, BusEvent, Delivery, JobOutcome, MachineId};

fn m(n: u8) -> MachineId {
    MachineId([n; 16])
}

#[tokio::test]
async fn report_notices_coalesce_per_machine() {
    let bus = Bus::new();
    let mut sub = bus.subscribe("incidents");
    for i in 0..10_000u32 {
        bus.publish(BusEvent::ReportIngested { machine: m((i % 3) as u8) }).await;
    }
    assert_eq!(sub.pending_notices(), 3);
    let mut got = Vec::new();
    for _ in 0..3 {
        match sub.recv().await {
            Some(Delivery::Notice(machine)) => got.push(machine),
            other => panic!("expected a notice, got {other:?}"),
        }
    }
    got.sort_by_key(|x| x.0);
    assert_eq!(got, vec![m(0), m(1), m(2)]);
}

#[tokio::test]
async fn notice_send_never_waits_on_stalled_consumer() {
    let bus = Bus::new();
    let _stalled = bus.subscribe("incidents"); // never reads
    let start = Instant::now();
    for i in 0..10_000u32 {
        bus.publish(BusEvent::ReportIngested { machine: m((i % 200) as u8) }).await;
    }
    assert!(start.elapsed() < Duration::from_millis(50), "took {:?}", start.elapsed());
}

#[tokio::test(flavor = "multi_thread")]
async fn state_events_are_never_dropped() {
    let bus = Bus::new();
    let mut sub = bus.subscribe("web");
    let sender = {
        let bus = bus.clone();
        tokio::spawn(async move {
            for i in 0..3000u32 {
                bus.publish(BusEvent::IncidentChanged { id: i.to_be_bytes().repeat(4).try_into().unwrap() }).await;
            }
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!sender.is_finished(), "the sender waits while the queue (1024) is full");
    let mut n = 0;
    while n < 3000 {
        match tokio::time::timeout(Duration::from_secs(5), sub.recv()).await {
            Ok(Some(Delivery::Event(BusEvent::IncidentChanged { .. }))) => n += 1,
            other => panic!("expected an incident event, got {other:?}"),
        }
    }
    sender.await.unwrap();
    assert_eq!(n, 3000);
}

#[tokio::test]
async fn job_finished_from_actions_does_not_wait() {
    let bus = Bus::new();
    let mut incidents = bus.subscribe("incidents");
    for i in 0..1024u32 {
        bus.publish(BusEvent::IncidentChanged { id: i.to_be_bytes().repeat(4).try_into().unwrap() }).await;
    }
    let start = Instant::now();
    let missed = bus.publish_job_finished([7; 16], JobOutcome::Succeeded);
    assert!(start.elapsed() < Duration::from_millis(10), "Actions never waits");
    assert_eq!(missed, 1, "the full Incidents queue missed it");
    // Reconciliation: the consumer learns about jobs that finished while its queue was full.
    assert_eq!(incidents.take_missed_jobs(), vec![[7; 16]]);
}
