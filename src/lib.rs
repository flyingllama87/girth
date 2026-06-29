//! girth - a FASP-inspired reliable bulk transfer over UDP for long fat
//! networks (high bandwidth-delay product).
//!
//! Two planes:
//!   - Control plane (TCP): session setup, file metadata, checksum + key exchange.
//!   - Data plane (UDP): DATA (sender->receiver), FEEDBACK (receiver->sender),
//!     START (receiver->sender first contact), FIN (sender->receiver end).
//!
//! The receiver is the "brain": it measures RTT, computes the RTO, schedules
//! retransmission requests (NACKs), and (in adaptive mode) computes the target
//! rate. The sender is "dumb": it paces injection at the target rate, services
//! retransmissions before new data, and echoes timing ticks.

pub mod auth;
pub mod control;
pub mod crypto;
pub mod error;
pub mod io;
pub mod log;
pub mod losstracker;
pub mod protocol;
pub mod rate;
pub mod receiver;
pub mod runtime;
pub mod sender;
pub mod stats;
pub mod sys;
pub mod transfer;
pub mod util;

pub use control::{default_params, TransferParams, MODE_RECV, MODE_SEND};
pub use error::GirthError;
pub use io::{source_crc32c, BlockSink, BlockSource, FileSink, FileSource, MemSink, MemSource};
pub use protocol::{DEFAULT_BLOCK_SIZE, PROTOCOL_VERSION};
pub use rate::RateWarmStart;
pub use runtime::{TransferControl, TransferHandle, TransferPhase};
pub use stats::{Stats, StatsSnapshot};
pub use transfer::{
    client_recv, client_recv_into, client_recv_into_with_handle, client_send, client_send_from,
    client_send_from_with_handle, AuthContext, Authorizer, ClientSession, Server, ServerLimits,
    SinkResolver, SourceResolver,
};
