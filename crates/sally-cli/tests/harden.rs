//! `secrets::harden` (architect Q108), alone in its own test binary: it makes the whole process
//! non-dumpable, which would change `/proc/self` for any test sharing the process.
#![allow(clippy::unwrap_used)]

use rustix::process::{DumpableBehavior, Resource, dumpable_behavior, getrlimit};

#[test]
fn harden_turns_core_dumps_off_and_makes_the_process_non_dumpable() {
    sally_cli::secrets::harden().unwrap();
    let core = getrlimit(Resource::Core);
    assert_eq!((core.current, core.maximum), (Some(0), Some(0)));
    assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
}
