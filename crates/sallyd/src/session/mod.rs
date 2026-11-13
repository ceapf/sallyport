//! Sessions (Task 12): the registry that owns every live session, and the per-session pieces it
//! assembles around the sandbox driver.

pub mod exit;
pub mod lookup;
pub mod types;

mod registry;
mod supervise;

pub use registry::{
    AGENT_SOCK, Registry, RegistryParts, SessionInfo, SessionState, StartError, StopOutcome,
};
pub use types::StopReason;
