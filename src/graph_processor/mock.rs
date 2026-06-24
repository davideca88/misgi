use std::collections::HashSet;

use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use petgraph::{Directed, Graph};
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use thiserror::Error;

use crate::graph_processor::model::GraphModel;

#[derive(Debug, Error, Clone, Copy, PartialEq)]
pub enum MockError {
    #[error(
        "pattern has more vertices ({pattern_vertices}) than the host \
         ({host_vertices}); the pattern cannot be embedded"
    )]
    PatternLargerThanHost {
        pattern_vertices: usize,
        host_vertices: usize,
    },

    #[error("pattern has no vertices; there is nothing to inject")]
    EmptyPattern,

    #[error("perturbation_percentage must be within [0.0, 1.0], got {0}")]
    InvalidPercentage(f64),

    #[error("add_ratio must be within [0.0, 1.0], got {0}")]
    InvalidAddRatio(f64),
}

/// Tunable parameters for [`inject_subgraph`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MockConfig {
    /// Fraction of the host's original edge count (`P`, in `[0.0, 1.0]`)
    /// that will be added or removed as perturbation, on top of whatever
    /// edges were required to embed the pattern.
    pub perturbation_percentage: f64,

    /// Fraction of the perturbation budget spent on additions; the
    /// remainder (`1.0 - add_ratio`) is spent on removals. Must be within
    /// `[0.0, 1.0]`.
    pub add_ratio: f64,

    /// Seed for the deterministic RNG, so the same inputs always produce
    /// the same `G'`.
    pub seed: u64,
}

impl Default for MockConfig {
    fn default() -> Self {
        Self {
            perturbation_percentage: 0.0,
            add_ratio: 0.5,
            seed: 42,
        }
    }
}

/// Statistics describing how `G'` was derived from `G` and `F`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockReport {
    /// Number of edges added during the perturbation phase.
    pub edges_added_for_perturbation: usize,

    /// Number of edges removed during the perturbation phase.
    pub edges_removed_for_perturbation: usize,
}

/// Output of [`inject_subgraph`]: the generated `G'` plus a report
/// describing how it was built.
#[derive(Debug)]
pub struct MockResult {
    pub graph: GraphModel,
    pub report: MockReport,
}

/// Injects `pattern` into `host`, producing `G'`.
///
/// See the module documentation for the two-phase algorithm description.
pub fn inject_subgraph(
    pattern: &GraphModel,
    host: &GraphModel,
    config: &MockConfig,
) -> Result<MockResult, MockError> {
    validate(pattern, host, config)?;

    let mut rng = ChaCha8Rng::seed_from_u64(config.seed);

    // Work on a clone of the host's graph; `host` itself is left untouched.
    let mut graph = host.graph.clone();

    // Captured *before* the pattern is embedded: perturbation budgets are
    // relative to the host's original edge count, not the (larger) edge
    // count after `F` has been injected.
    let baseline_edge_count = graph.edge_count();

    let protected = embed_pattern(&mut graph, pattern, &mut rng);

    let (edges_added_for_perturbation, edges_removed_for_perturbation) = apply_perturbation(
        &mut graph,
        &protected,
        baseline_edge_count,
        config,
        &mut rng,
    );

    Ok(MockResult {
        graph: GraphModel { graph },
        report: MockReport {
            edges_added_for_perturbation,
            edges_removed_for_perturbation,
        },
    })
}

fn validate(pattern: &GraphModel, host: &GraphModel, config: &MockConfig) -> Result<(), MockError> {
    if pattern.vertex_count() == 0 {
        return Err(MockError::EmptyPattern);
    }

    if pattern.vertex_count() > host.vertex_count() {
        return Err(MockError::PatternLargerThanHost {
            pattern_vertices: pattern.vertex_count(),
            host_vertices: host.vertex_count(),
        });
    }

    if !(0.0..=1.0).contains(&config.perturbation_percentage) {
        return Err(MockError::InvalidPercentage(config.perturbation_percentage));
    }

    if !(0.0..=1.0).contains(&config.add_ratio) {
        return Err(MockError::InvalidAddRatio(config.add_ratio));
    }

    Ok(())
}

/// Embeds `pattern` into `graph` as a non-induced subgraph: a random
/// bijection is drawn from the pattern's vertices onto a random subset of
/// the host's vertices, and every edge of the pattern (including
/// self-loops) is mapped through that bijection and added to `graph` if
/// it isn't already there.
///
/// Returns the set of (host) edge endpoints that resulted from the
/// pattern, in host `NodeIndex` space — these must never be removed
/// during perturbation, since doing so would break the guarantee that
/// `pattern` is embedded in the result.
fn embed_pattern(
    graph: &mut Graph<(), (), Directed>,
    pattern: &GraphModel,
    rng: &mut ChaCha8Rng,
) -> HashSet<(NodeIndex, NodeIndex)> {
    let mut host_nodes: Vec<NodeIndex> = graph.node_indices().collect();
    host_nodes.shuffle(rng);
    host_nodes.truncate(pattern.vertex_count());

    // `mapping[i]` is the host vertex chosen to represent pattern vertex
    // `i`. Pattern vertices are always indexed `0..vertex_count()` (no
    // node is ever removed from a `GraphModel`), so this is a safe,
    // direct lookup.
    let mapping = host_nodes;

    let mut protected = HashSet::with_capacity(pattern.graph.edge_count());

    for edge in pattern.graph.edge_references() {
        let host_source = mapping[edge.source().index()];
        let host_target = mapping[edge.target().index()];

        // Embedding is non-induced: we only ever *add* edges required by
        // the pattern, never relying on edges that might already exist
        // between the mapped vertices by chance.
        if graph.find_edge(host_source, host_target).is_none() {
            graph.add_edge(host_source, host_target, ());
        }

        protected.insert((host_source, host_target));
    }

    protected
}

/// Splits `P` (relative to the host's original edge count) into an
/// addition budget and a removal budget according to `add_ratio`, then
/// applies both. Returns `(edges_added, edges_removed)`.
fn apply_perturbation(
    graph: &mut Graph<(), (), Directed>,
    protected: &HashSet<(NodeIndex, NodeIndex)>,
    baseline_edge_count: usize,
    config: &MockConfig,
    rng: &mut ChaCha8Rng,
) -> (usize, usize) {
    let total_changes =
        (config.perturbation_percentage * baseline_edge_count as f64).round() as usize;
    let target_additions = (total_changes as f64 * config.add_ratio).round() as usize;
    let target_removals = total_changes.saturating_sub(target_additions);

    let removed = remove_random_edges(graph, protected, target_removals, rng);
    let added = add_random_edges(graph, target_additions, rng);

    (added, removed)
}

/// Removes up to `target_removals` random edges, never touching a
/// `protected` one. If fewer than `target_removals` non-protected edges
/// exist, removes as many as are available.
fn remove_random_edges(
    graph: &mut Graph<(), (), Directed>,
    protected: &HashSet<(NodeIndex, NodeIndex)>,
    target_removals: usize,
    rng: &mut ChaCha8Rng,
) -> usize {
    if target_removals == 0 {
        return 0;
    }

    let mut removable: Vec<(NodeIndex, NodeIndex)> = graph
        .edge_references()
        .map(|edge| (edge.source(), edge.target()))
        .filter(|endpoints| !protected.contains(endpoints))
        .collect();

    removable.shuffle(rng);
    removable.truncate(target_removals);

    let mut removed = 0;
    for (source, target) in removable {
        // Edge indices shift on removal (petgraph swap-removes), so the
        // edge is re-located by its stable endpoints rather than by a
        // previously captured EdgeIndex.
        if let Some(edge_index) = graph.find_edge(source, target) {
            graph.remove_edge(edge_index);
            removed += 1;
        }
    }

    removed
}

/// Adds up to `target_additions` random edges between distinct vertices
/// that are not already connected. Self-loops are intentionally not
/// generated by perturbation, to keep the synthetic noise simple.
fn add_random_edges(
    graph: &mut Graph<(), (), Directed>,
    target_additions: usize,
    rng: &mut ChaCha8Rng,
) -> usize {
    if target_additions == 0 {
        return 0;
    }

    let nodes: Vec<NodeIndex> = graph.node_indices().collect();
    if nodes.len() < 2 {
        return 0;
    }

    let mut added = 0;
    // A graph that is already near-complete may not have room for
    // `target_additions` new edges, so attempts are capped instead of
    // looping forever looking for a non-existent free pair.
    let max_attempts = target_additions.saturating_mul(20).max(20);
    let mut attempts = 0;

    while added < target_additions && attempts < max_attempts {
        attempts += 1;

        let source = nodes[rng.gen_range(0..nodes.len())];
        let target = nodes[rng.gen_range(0..nodes.len())];

        if source == target || graph.find_edge(source, target).is_some() {
            continue;
        }

        graph.add_edge(source, target, ());
        added += 1;
    }

    added
}
