use std::collections::HashMap;

use petgraph::graph::{EdgeIndex, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::{Directed, Graph};
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use thiserror::Error;

use crate::graph_processor::model::GraphModel;

#[derive(Debug, Error, Clone, Copy, PartialEq)]
pub enum MockError {
    #[error("pattern has no vertices; there is nothing to inject")]
    EmptyPattern,

    #[error("perturbation_percentage must be within [0.0, 1.0], got {0}")]
    InvalidPercentage(f64),

    #[error("add_ratio must be within [0.0, 1.0], got {0}")]
    InvalidAddRatio(f64),

    #[error("injection_ratio must be non-negative, got {0}")]
    InvalidInjectionRatio(f64),
}

/// Tunable parameters for [`inject_subgraph`].
///
/// # Pipeline
///
/// 1. `pattern` (`P`) is perturbed in isolation — independently of
///    `target` — producing an intermediate pattern `P'`. This phase adds
///    and/or removes edges of `P` so that downstream isomorphism /
///    monomorphism checks can be validated against both false negatives
///    (edges added to `P` before injection) and false positives (edges
///    removed from `P` before injection).
/// 2. `P'` is injected into `target` (`T`) as a *new, disjoint set of
///    vertices* (i.e. `T'` contains every vertex/edge of `T`, plus every
///    vertex/edge of `P'`, plus a number of extra "bridge" edges
///    connecting the two parts). This is the procedure requested by
///    [`inject_subgraph`] itself.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MockConfig {
    /// Fraction of `pattern`'s edge count (`|E(P)|`, in `[0.0, 1.0]`) that
    /// will be added and/or removed from `pattern` *before* injection,
    /// producing the intermediate pattern `P'`. `0.0` means `P'` is
    /// identical to `P` (no perturbation); `1.0` means every edge of `P`
    /// is subject to perturbation. The resulting count is always rounded
    /// up.
    pub perturbation_percentage: f64,

    /// Fraction of `P'`'s edge count (`|E(P')|`) used as the number of
    /// "bridge" edges connecting `P'` to `target` during injection.
    /// `0.0` means `P'` is injected as a brand-new, disconnected
    /// component; `1.0` means as many bridge edges as `P'` has edges;
    /// values greater than `1.0` are allowed and simply request more
    /// bridge edges than `P'` has edges. The resulting count is always
    /// rounded up. Must be non-negative.
    pub injection_ratio: f64,

    /// Fraction of the perturbation budget (computed from
    /// `perturbation_percentage`) spent on additions; the remainder
    /// (`1.0 - add_ratio`) is spent on removals. Must be within
    /// `[0.0, 1.0]`. Additions are always applied before removals.
    pub add_ratio: f64,

    /// Seed for the deterministic RNG, so the same inputs always produce
    /// the same `G'`.
    pub seed: u64,
}

impl Default for MockConfig {
    fn default() -> Self {
        Self {
            perturbation_percentage: 0.0,
            injection_ratio: 0.0,
            add_ratio: 0.0,
            seed: 42,
        }
    }
}

/// Statistics describing how `T'` was derived from `T` and `P`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockReport {
    /// Number of edges added to `pattern` while building `P'` (phase 1).
    pub pattern_edges_added: usize,

    /// Number of edges removed from `pattern` while building `P'`
    /// (phase 1).
    pub pattern_edges_removed: usize,

    /// Number of "bridge" edges added between `P'` and `target` while
    /// injecting `P'` into `target` (phase 2).
    pub injection_edges_added: usize,
}

/// Output of [`inject_subgraph`]: the generated `T'` plus a report
/// describing how it was built.
#[derive(Debug)]
pub struct MockResult {
    pub graph: GraphModel,
    pub report: MockReport,
}

/// Builds `T'` by perturbing `pattern` into an intermediate `P'` and then
/// injecting `P'` into `target` as a new, disjoint set of vertices.
///
/// See the module documentation for the two-phase algorithm description.
pub fn inject_subgraph(
    pattern: &GraphModel,
    target: &GraphModel,
    config: &MockConfig,
) -> Result<MockResult, MockError> {
    validate(pattern, config)?;

    let mut rng = ChaCha8Rng::seed_from_u64(config.seed);

    // --- Phase 1: perturb `pattern` in isolation, producing `P'`. -------
    // Work on a clone; `pattern` itself is left untouched.
    let mut p_prime = pattern.graph.clone();

    let baseline_pattern_edges = p_prime.edge_count();
    let total_changes = (config.perturbation_percentage * baseline_pattern_edges as f64).ceil() as usize;
    let target_additions = (total_changes as f64 * config.add_ratio).ceil() as usize;
    let target_removals = total_changes.saturating_sub(target_additions);

    // Additions always happen before removals.
    let pattern_edges_added = add_random_edges(&mut p_prime, target_additions, &mut rng);
    let pattern_edges_removed =
        remove_safe_edges(&mut p_prime, target_removals, &mut rng);

    // --- Phase 2: inject `P'` into `target` as a disjoint component. ----
    // Work on a clone of the target's graph; `target` itself is left
    // untouched.
    let mut graph = target.graph.clone();
    let target_nodes: Vec<NodeIndex> = graph.node_indices().collect();

    // `P'`'s vertices are copied in as brand-new vertices of `graph` —
    // they never reuse or merge with an existing vertex of `target`.
    let mut mapping: HashMap<NodeIndex, NodeIndex> = HashMap::with_capacity(p_prime.node_count());
    for node in p_prime.node_indices() {
        mapping.insert(node, graph.add_node(()));
    }
    for edge in p_prime.edge_references() {
        let host_source = mapping[&edge.source()];
        let host_target = mapping[&edge.target()];
        graph.add_edge(host_source, host_target, ());
    }
    let pattern_nodes_in_mock: Vec<NodeIndex> = mapping.values().copied().collect();

    let injection_edges_target =
        (config.injection_ratio * p_prime.edge_count() as f64).ceil() as usize;
    let injection_edges_added = add_injection_edges(
        &mut graph,
        &target_nodes,
        &pattern_nodes_in_mock,
        injection_edges_target,
        &mut rng,
    );

    Ok(MockResult {
        graph: GraphModel { graph },
        report: MockReport {
            pattern_edges_added,
            pattern_edges_removed,
            injection_edges_added,
        },
    })
}

fn validate(pattern: &GraphModel, config: &MockConfig) -> Result<(), MockError> {
    if pattern.vertex_count() == 0 {
        return Err(MockError::EmptyPattern);
    }

    if !(0.0..=1.0).contains(&config.perturbation_percentage) {
        return Err(MockError::InvalidPercentage(config.perturbation_percentage));
    }

    if !(0.0..=1.0).contains(&config.add_ratio) {
        return Err(MockError::InvalidAddRatio(config.add_ratio));
    }

    if config.injection_ratio < 0.0 {
        return Err(MockError::InvalidInjectionRatio(config.injection_ratio));
    }

    Ok(())
}

/// Adds up to `target_additions` random edges between distinct vertices
/// of `graph` that aren't already connected *in that direction* (i.e. a
/// pair of vertices may end up with up to two edges between them, one in
/// each direction, but never two parallel edges in the same direction).
/// Self-loops are intentionally not generated, to keep the synthetic
/// noise simple.
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

/// Adds up to `target_additions` random "bridge" edges between the
/// pattern's vertices (now copied into `graph`) and the target's
/// original vertices. Direction is chosen at random for each edge, and —
/// as with [`add_random_edges`] — at most one edge per direction is ever
/// created between a given pair of vertices.
fn add_injection_edges(
    graph: &mut Graph<(), (), Directed>,
    target_nodes: &[NodeIndex],
    pattern_nodes: &[NodeIndex],
    target_additions: usize,
    rng: &mut ChaCha8Rng,
) -> usize {
    if target_additions == 0 || target_nodes.is_empty() || pattern_nodes.is_empty() {
        return 0;
    }

    let mut added = 0;
    let max_attempts = target_additions.saturating_mul(20).max(20);
    let mut attempts = 0;

    while added < target_additions && attempts < max_attempts {
        attempts += 1;

        let pattern_node = pattern_nodes[rng.gen_range(0..pattern_nodes.len())];
        let target_node = target_nodes[rng.gen_range(0..target_nodes.len())];

        let (source, target) = if rng.gen_bool(0.5) {
            (pattern_node, target_node)
        } else {
            (target_node, pattern_node)
        };

        if graph.find_edge(source, target).is_some() {
            continue;
        }

        graph.add_edge(source, target, ());
        added += 1;
    }

    added
}

/// Removes up to `target_removals` random edges from `graph`, never
/// removing an edge that would increase the number of (weakly connected)
/// components — i.e. never removing a cut edge ("bridge"). If, at any
/// point, every remaining edge is a bridge, removal stops early even if
/// `target_removals` hasn't been reached yet, since the business rule
/// that `P'` must never gain components than `P` had takes priority over
/// hitting the perturbation budget exactly.
///
/// Direction is ignored when reasoning about connectivity: a pair of
/// vertices is considered connected as long as *some* path — in either
/// direction — links them.
fn remove_safe_edges(
    graph: &mut Graph<(), (), Directed>,
    target_removals: usize,
    rng: &mut ChaCha8Rng,
) -> usize {
    let mut removed = 0;

    while removed < target_removals {
        let mut safe = safe_to_remove_edges(graph);
        if safe.is_empty() {
            break;
        }

        safe.shuffle(rng);
        graph.remove_edge(safe[0]);
        removed += 1;
    }

    removed
}

/// Returns every edge of `graph` whose removal would *not* change the
/// number of weakly connected components — i.e. every non-bridge edge.
/// A self-loop's endpoints are trivially always in the same component,
/// so self-loops are always considered safe to remove.
///
/// This recomputes connectivity from scratch (via a small union-find)
/// for every candidate edge, which is intentionally simple rather than
/// using an incremental bridge-finding algorithm: these mock graphs are
/// small test fixtures, so clarity is favored over asymptotic
/// performance.
fn safe_to_remove_edges(graph: &Graph<(), (), Directed>) -> Vec<EdgeIndex> {
    let node_count = graph.node_count();
    let edges: Vec<(NodeIndex, NodeIndex, EdgeIndex)> = graph
        .edge_references()
        .map(|edge| (edge.source(), edge.target(), edge.id()))
        .collect();

    let mut safe = Vec::new();

    for (candidate_idx, &(source, target, edge_id)) in edges.iter().enumerate() {
        let mut parent: Vec<usize> = (0..node_count).collect();

        for (other_idx, &(other_source, other_target, _)) in edges.iter().enumerate() {
            if other_idx == candidate_idx {
                continue;
            }
            union(&mut parent, other_source.index(), other_target.index());
        }

        if find(&mut parent, source.index()) == find(&mut parent, target.index()) {
            safe.push(edge_id);
        }
    }

    safe
}

fn find(parent: &mut [usize], x: usize) -> usize {
    if parent[x] != x {
        parent[x] = find(parent, parent[x]);
    }
    parent[x]
}

fn union(parent: &mut [usize], a: usize, b: usize) {
    let root_a = find(parent, a);
    let root_b = find(parent, b);
    if root_a != root_b {
        parent[root_a] = root_b;
    }
}
