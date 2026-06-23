use std::collections::{HashMap, HashSet};
use std::ops::Range;

use petgraph::graph::NodeIndex;
use petgraph::{Directed, Direction, Graph};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Deserialize)]
struct JsonGraph {
    vertices: Vec<u64>,
    edges: Vec<[u64; 2]>,
}

#[derive(Debug, Error)]
pub enum GraphModelError {
    #[error("invalid graph JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("duplicate vertex ID: {0}")]
    DuplicateVertex(u64),

    #[error("edge references missing source vertex: {0}")]
    MissingSourceVertex(u64),

    #[error("edge references missing target vertex: {0}")]
    MissingTargetVertex(u64),
}

#[derive(Debug)]
pub struct GraphModel {
    pub(crate) graph: Graph<(), (), Directed>,
}

impl GraphModel {
    pub fn from_json(input: &str) -> Result<Self, GraphModelError> {
        let parsed: JsonGraph = serde_json::from_str(input)?;
        Self::from_parts(parsed.vertices, parsed.edges)
    }

    fn from_parts(vertices: Vec<u64>, edges: Vec<[u64; 2]>) -> Result<Self, GraphModelError> {
        let mut graph = Graph::<(), (), Directed>::new();
        let mut external_to_internal = HashMap::with_capacity(vertices.len());

        for vertex_id in vertices {
            if external_to_internal.contains_key(&vertex_id) {
                return Err(GraphModelError::DuplicateVertex(vertex_id));
            }

            let node_index = graph.add_node(());
            external_to_internal.insert(vertex_id, node_index);
        }

        let mut logical_edges = HashSet::new();

        for [source_id, target_id] in edges {
            let source = external_to_internal
                .get(&source_id)
                .copied()
                .ok_or(GraphModelError::MissingSourceVertex(source_id))?;
            let target = external_to_internal
                .get(&target_id)
                .copied()
                .ok_or(GraphModelError::MissingTargetVertex(target_id))?;

            if logical_edges.insert((source_id, target_id)) {
                graph.add_edge(source, target, ());
            }
        }

        Ok(Self { graph })
    }

    pub fn vertex_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    pub fn vertex_indices(&self) -> Range<usize> {
        0..self.vertex_count()
    }

    pub fn in_degree(&self, index: usize) -> usize {
        let node = NodeIndex::new(index);
        self.graph
            .neighbors_directed(node, Direction::Incoming)
            .count()
    }

    pub fn out_degree(&self, index: usize) -> usize {
        let node = NodeIndex::new(index);
        self.graph
            .neighbors_directed(node, Direction::Outgoing)
            .count()
    }

    pub fn has_edge_by_index(&self, source_index: usize, target_index: usize) -> bool {
        let source = NodeIndex::new(source_index);
        let target = NodeIndex::new(target_index);
        self.graph.find_edge(source, target).is_some()
    }
}
