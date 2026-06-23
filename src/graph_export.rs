use std::ffi::OsStr;
use std::fmt::Write as _;

use petgraph::visit::EdgeRef;
use serde::Serialize;

use crate::graph_processor::GraphModel;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphExportFormat {
    Dot,
    Json,
    Gml,
}

impl GraphExportFormat {
    pub fn parse(value: &OsStr) -> Option<Self> {
        match value.to_string_lossy().to_ascii_lowercase().as_str() {
            "dot" => Some(Self::Dot),
            "json" => Some(Self::Json),
            "gml" => Some(Self::Gml),
            _ => None,
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::Dot => "dot",
            Self::Json => "json",
            Self::Gml => "gml",
        }
    }
}

#[derive(Debug, Serialize)]
struct ExportJsonGraph {
    vertices: Vec<usize>,
    edges: Vec<[usize; 2]>,
}

pub fn export_graph(graph: &GraphModel, format: GraphExportFormat) -> String {
    match format {
        GraphExportFormat::Dot => export_dot(graph),
        GraphExportFormat::Json => export_json(graph),
        GraphExportFormat::Gml => export_gml(graph),
    }
}

fn export_json(graph: &GraphModel) -> String {
    let json_graph = ExportJsonGraph {
        vertices: graph.vertex_indices().collect(),
        edges: logical_edges(graph),
    };

    serde_json::to_string_pretty(&json_graph).expect("serializing graph export should not fail")
}

fn export_dot(graph: &GraphModel) -> String {
    let mut output = String::from("digraph misgi {\n");

    for vertex in graph.vertex_indices() {
        writeln!(&mut output, "    {vertex};").expect("writing to a string should not fail");
    }

    for [source, target] in logical_edges(graph) {
        writeln!(&mut output, "    {source} -> {target};")
            .expect("writing to a string should not fail");
    }

    output.push_str("}\n");
    output
}

fn export_gml(graph: &GraphModel) -> String {
    let mut output = String::from("graph [\n    directed 1\n");

    for vertex in graph.vertex_indices() {
        writeln!(&mut output, "    node [ id {vertex} ]")
            .expect("writing to a string should not fail");
    }

    for [source, target] in logical_edges(graph) {
        writeln!(&mut output, "    edge [ source {source} target {target} ]")
            .expect("writing to a string should not fail");
    }

    output.push_str("]\n");
    output
}

fn logical_edges(graph: &GraphModel) -> Vec<[usize; 2]> {
    graph
        .graph
        .edge_references()
        .map(|edge| [edge.source().index(), edge.target().index()])
        .collect()
}
