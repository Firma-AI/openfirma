use std::sync::mpsc;
use std::time::Duration;

use crate::common;

#[test]
fn a_reader_waits_for_the_writer_to_release_the_lock() {
    let (_root, store) = common::store();
    let writer = store.exclusive().expect("exclusive lock");
    let (acquired, observed) = mpsc::channel();

    let reader = std::thread::spawn(move || {
        let _reader = store.shared().expect("shared lock");
        acquired.send(()).expect("report");
    });

    assert!(
        observed.recv_timeout(Duration::from_millis(300)).is_err(),
        "the reader got the lock while the writer held it"
    );
    drop(writer);
    observed
        .recv_timeout(Duration::from_secs(10))
        .expect("the reader gets the lock once the writer releases it");
    reader.join().expect("reader thread");
}
