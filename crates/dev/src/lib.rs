//! Stand-ins for the parts of Concurro a relay talks to, for developing
//! and testing the relay before Concurro has them: a registry which
//! approves every registration, a gateway which serves a harness through a
//! relay, and a mock provider.

pub mod gateway;
pub mod jobs;
pub mod provider;
pub mod registry;
pub mod slow;
pub mod tls;
