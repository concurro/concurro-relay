//! Concurro's side of a relay: receives relays' connections, has a relay
//! perform each inference request, and accepts a response only with a proof
//! that the provider received exactly that request.

pub mod accept;
pub mod exchange;
pub mod link;
pub mod live;
pub mod ws;
