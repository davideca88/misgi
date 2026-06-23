use std::path::Path;

use thiserror::Error;

use crate::graph_processor::reduction::reduce_fully;
use crate::graph_processor::ullmann::find_subgraph_mapping;
use crate::graph_processor::{GraphModel, GraphModelError};
use crate::re_engine::{analyze_binary_to_graph_json, ReEngineError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphSummary {
    pub vertices: usize,
    pub edges: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionReport {
    pub detected: bool,
    pub pattern: GraphSummary,
    pub target: GraphSummary,
    pub mapping: Option<Vec<(usize, usize)>>,
}

#[derive(Debug)]
pub struct DetectionAnalysis {
    pub report: DetectionReport,
    pub target_graph: GraphModel,
    pub malware_graph: GraphModel,
}

#[derive(Debug, Error)]
pub enum MisgiError {
    #[error("failed to analyze malware binary: {0}")]
    MalwareAnalysis(#[source] ReEngineError),

    #[error("failed to analyze target binary: {0}")]
    TargetAnalysis(#[source] ReEngineError),

    #[error("invalid malware graph: {0}")]
    MalwareGraph(#[source] GraphModelError),

    #[error("invalid target graph: {0}")]
    TargetGraph(#[source] GraphModelError),
}

pub fn analyze_match(
    target_binary: &Path,
    malware_binary: &Path,
) -> Result<DetectionReport, MisgiError> {
    Ok(analyze_detection(target_binary, malware_binary)?.report)
}

pub fn analyze_detection(
    target_binary: &Path,
    malware_binary: &Path,
) -> Result<DetectionAnalysis, MisgiError> {
    let malware_json =
        analyze_binary_to_graph_json(malware_binary).map_err(MisgiError::MalwareAnalysis)?;
    let target_json =
        analyze_binary_to_graph_json(target_binary).map_err(MisgiError::TargetAnalysis)?;

    analyze_detection_from_graph_json(&target_json, &malware_json)
}

pub fn analyze_match_from_graph_json(
    target_graph_json: &str,
    malware_graph_json: &str,
) -> Result<DetectionReport, MisgiError> {
    Ok(analyze_detection_from_graph_json(target_graph_json, malware_graph_json)?.report)
}

pub fn analyze_detection_from_graph_json(
    target_graph_json: &str,
    malware_graph_json: &str,
) -> Result<DetectionAnalysis, MisgiError> {
    let original_pattern =
        GraphModel::from_json(malware_graph_json).map_err(MisgiError::MalwareGraph)?;
    let mut reduced_pattern =
        GraphModel::from_json(malware_graph_json).map_err(MisgiError::MalwareGraph)?;

    let original_target =
        GraphModel::from_json(target_graph_json).map_err(MisgiError::TargetGraph)?;
    let mut reduced_target =
        GraphModel::from_json(target_graph_json).map_err(MisgiError::TargetGraph)?;

    reduce_fully(&mut reduced_pattern);
    let pattern = if original_pattern.vertex_count() > 0 && reduced_pattern.vertex_count() == 0 {
        original_pattern
    } else {
        reduced_pattern
    };

    reduce_fully(&mut reduced_target);
    let target = if original_target.vertex_count() > 0 && reduced_target.vertex_count() == 0 {
        original_target
    } else {
        reduced_target
    };

    let mapping = find_subgraph_mapping(&pattern, &target);
    let detected = mapping.is_some();
    let report = DetectionReport {
        detected,
        pattern: summarize(&pattern),
        target: summarize(&target),
        mapping,
    };

    Ok(DetectionAnalysis {
        report,
        target_graph: target,
        malware_graph: pattern,
    })
}

fn summarize(graph: &GraphModel) -> GraphSummary {
    GraphSummary {
        vertices: graph.vertex_count(),
        edges: graph.edge_count(),
    }
}
