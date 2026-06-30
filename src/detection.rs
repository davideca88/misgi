use std::path::Path;

use thiserror::Error;

use crate::graph_processor::mock::{inject_subgraph, MockConfig, MockError, MockReport};
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

#[derive(Debug)]
pub struct MockDetectionAnalysis {
    pub report: DetectionReport,
    pub original_target_graph: GraphModel,
    pub target_mock_graph: GraphModel,
    pub malware_graph: GraphModel,
    pub mock_report: MockReport,
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

    #[error("failed to generate mocked target graph: {0}")]
    MockInjection(#[source] MockError),
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

pub fn analyze_detection_with_mock(
    target_binary: &Path,
    malware_binary: &Path,
    mock_config: &MockConfig,
) -> Result<MockDetectionAnalysis, MisgiError> {
    let malware_json =
        analyze_binary_to_graph_json(malware_binary).map_err(MisgiError::MalwareAnalysis)?;
    let target_json =
        analyze_binary_to_graph_json(target_binary).map_err(MisgiError::TargetAnalysis)?;

    analyze_detection_with_mock_from_graph_json(&target_json, &malware_json, mock_config)
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
    let prepared = prepare_graphs(target_graph_json, malware_graph_json)?;
    let report = build_report(&prepared.pattern, &prepared.target);

    Ok(DetectionAnalysis {
        report,
        target_graph: prepared.target,
        malware_graph: prepared.pattern,
    })
}

pub fn analyze_detection_with_mock_from_graph_json(
    target_graph_json: &str,
    malware_graph_json: &str,
    mock_config: &MockConfig,
) -> Result<MockDetectionAnalysis, MisgiError> {
    let prepared = prepare_graphs(target_graph_json, malware_graph_json)?;
    let mock_result = inject_subgraph(&prepared.pattern, &prepared.target, mock_config)
        .map_err(MisgiError::MockInjection)?;
    let report = build_report(&prepared.pattern, &mock_result.graph);

    Ok(MockDetectionAnalysis {
        report,
        original_target_graph: prepared.original_target,
        target_mock_graph: mock_result.graph,
        malware_graph: prepared.pattern,
        mock_report: mock_result.report,
    })
}

struct PreparedGraphs {
    pattern: GraphModel,
    target: GraphModel,
    original_target: GraphModel,
}

fn prepare_graphs(
    target_graph_json: &str,
    malware_graph_json: &str,
) -> Result<PreparedGraphs, MisgiError> {
    let original_pattern =
        GraphModel::from_json(malware_graph_json).map_err(MisgiError::MalwareGraph)?;
    let mut reduced_pattern =
        GraphModel::from_json(malware_graph_json).map_err(MisgiError::MalwareGraph)?;

    let target_for_fallback =
        GraphModel::from_json(target_graph_json).map_err(MisgiError::TargetGraph)?;
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
    let target = if target_for_fallback.vertex_count() > 0 && reduced_target.vertex_count() == 0 {
        target_for_fallback
    } else {
        reduced_target
    };

    Ok(PreparedGraphs {
        pattern,
        target,
        original_target,
    })
}

fn build_report(pattern: &GraphModel, target: &GraphModel) -> DetectionReport {
    let mapping = find_subgraph_mapping(pattern, target);
    DetectionReport {
        detected: mapping.is_some(),
        pattern: summarize(pattern),
        target: summarize(target),
        mapping,
    }
}

fn summarize(graph: &GraphModel) -> GraphSummary {
    GraphSummary {
        vertices: graph.vertex_count(),
        edges: graph.edge_count(),
    }
}
