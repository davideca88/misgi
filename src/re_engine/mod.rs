mod builder;
mod radare;

pub use builder::{build_dependency_graph_json, Instruction};
pub use radare::analyze_binary_to_graph_json;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReEngineError {
    #[error("radare2 pipe failed: {0}")]
    RadarePipe(#[from] r2pipe::Error),

    #[error("invalid radare2 JSON: {0}")]
    InvalidRadareJson(#[from] serde_json::Error),

    #[error("main function was not found in radare2 output")]
    MainFunctionNotFound,

    #[error("radare2 returned an instruction without an address")]
    MissingInstructionAddress,
}
