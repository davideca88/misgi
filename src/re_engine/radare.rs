use std::path::Path;

use r2pipe::{R2Pipe, R2PipeSpawnOptions};

use serde::Deserialize;

use super::{build_dependency_graph_json, builder::Instruction, ReEngineError};

#[derive(Debug, Deserialize)]
struct RadareFunction {
    blocks: Option<Vec<RadareBlock>>,
}

#[derive(Debug, Deserialize)]
struct RadareBlock {
    ops: Option<Vec<RadareOp>>,
}

#[derive(Debug, Deserialize)]
struct RadareOp {
    addr: Option<u64>,
    offset: Option<u64>,
    esil: Option<String>,
}

pub fn analyze_binary_to_graph_json(path: &Path) -> Result<String, ReEngineError> {
    let options = R2PipeSpawnOptions {
        args: vec!["-2"],
        ..Default::default()
    };
    let mut r2 = R2Pipe::spawn(path.to_string_lossy().into_owned(), Some(options))?;
    r2.cmd("aaa")?;
    r2.cmd("s main")?;

    let function_json = r2.cmd("agfj")?;
    r2.close();

    let functions: Vec<RadareFunction> = serde_json::from_str(&function_json)?;
    let function = functions
        .into_iter()
        .next()
        .ok_or(ReEngineError::MainFunctionNotFound)?;

    let mut instructions = Vec::new();

    for block in function.blocks.unwrap_or_default() {
        for op in block.ops.unwrap_or_default() {
            let address = op
                .addr
                .or(op.offset)
                .ok_or(ReEngineError::MissingInstructionAddress)?;

            instructions.push(Instruction::new(address, op.esil.unwrap_or_default()));
        }
    }

    Ok(build_dependency_graph_json(&instructions))
}
