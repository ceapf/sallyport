use super::*;

/// The bounds are the values chosen for this client; changing one is a reviewed decision.
#[test]
fn the_bounds_are_pinned() {
    assert_eq!(MAX_LIST_BYTES, 8 * 1024 * 1024);
    assert_eq!(MAX_SIBLINGS, 10_000);
    assert_eq!(MAX_PATH_BYTES, 1024);
    assert_eq!(MAX_SEGMENT_BYTES, 255);
    assert_eq!(MAX_REPO_PART_BYTES, 96);
    assert_eq!(MAX_REVISION_BYTES, 128);
    assert_eq!(MAX_FILE_SIZE, 1 << 40);
    assert_eq!(MAX_REDIRECTS, 3);
    assert_eq!(MAX_RETRIES, 3);
    assert_eq!(MAX_RETRY_WAIT_SECS, 60);
    assert_eq!(DEFAULT_RETRY_WAIT_SECS, 5);
    assert_eq!(MAX_LOCATION_BYTES, 4096);
    assert_eq!(SHOWN_NAME_BYTES, 128);
}

/// The default wait is within the cap.
const _: () = assert!(DEFAULT_RETRY_WAIT_SECS <= MAX_RETRY_WAIT_SECS);
