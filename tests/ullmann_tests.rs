use misgi::graph_processor::model::GraphModel;
use misgi::graph_processor::ullmann::{contains_subgraph, find_subgraph_mapping};

fn graph(vertices: &[u64], edges: &[[u64; 2]]) -> GraphModel {
    let vertices_json = vertices
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let edges_json = edges
        .iter()
        .map(|[source, target]| format!("[{source}, {target}]"))
        .collect::<Vec<_>>()
        .join(", ");
    let json = format!(r#"{{"vertices": [{vertices_json}], "edges": [{edges_json}]}}"#);

    GraphModel::from_json(&json).expect("test graph should be valid")
}

#[test]
fn empty_pattern_matches_any_target() {
    let pattern = graph(&[], &[]);
    let target = graph(&[1, 2], &[[1, 2]]);

    assert!(contains_subgraph(&pattern, &target));
    assert_eq!(find_subgraph_mapping(&pattern, &target), Some(Vec::new()));
}

#[test]
fn non_empty_pattern_does_not_match_empty_target() {
    let pattern = graph(&[1], &[]);
    let target = graph(&[], &[]);

    assert!(!contains_subgraph(&pattern, &target));
}

#[test]
fn exact_graph_match_succeeds() {
    let pattern = graph(&[1, 2, 3], &[[1, 2], [2, 3]]);
    let target = graph(&[10, 20, 30], &[[10, 20], [20, 30]]);

    assert!(contains_subgraph(&pattern, &target));
}

#[test]
fn smaller_pattern_inside_larger_target_succeeds() {
    let pattern = graph(&[1, 2], &[[1, 2]]);
    let target = graph(&[10, 20, 30], &[[10, 20], [20, 30]]);

    assert!(contains_subgraph(&pattern, &target));
}

#[test]
fn pattern_larger_than_target_fails() {
    let pattern = graph(&[1, 2, 3], &[]);
    let target = graph(&[10, 20], &[]);

    assert!(!contains_subgraph(&pattern, &target));
}

#[test]
fn missing_required_edge_fails() {
    let pattern = graph(&[1, 2], &[[1, 2]]);
    let target = graph(&[10, 20], &[]);

    assert!(!contains_subgraph(&pattern, &target));
}

#[test]
fn reversed_directed_edge_fails() {
    let pattern = graph(&[1, 2], &[[1, 1], [1, 2]]);
    let target = graph(&[10, 20], &[[10, 10], [20, 10]]);

    assert!(!contains_subgraph(&pattern, &target));
}

#[test]
fn extra_target_edges_are_allowed() {
    let pattern = graph(&[1, 2], &[[1, 2]]);
    let target = graph(&[10, 20], &[[10, 20], [20, 10]]);

    assert!(contains_subgraph(&pattern, &target));
}

#[test]
fn branching_graph_match_succeeds() {
    let pattern = graph(&[1, 2, 3], &[[1, 2], [1, 3]]);
    let target = graph(&[10, 20, 30, 40], &[[10, 20], [10, 30], [20, 40], [30, 40]]);

    assert!(contains_subgraph(&pattern, &target));
}

#[test]
fn disconnected_pattern_match_succeeds_when_all_components_map() {
    let pattern = graph(&[1, 2, 3, 4], &[[1, 2], [3, 4]]);
    let target = graph(&[10, 20, 30, 40, 50], &[[10, 20], [30, 40], [40, 50]]);

    assert!(contains_subgraph(&pattern, &target));
}

#[test]
fn disconnected_pattern_fails_when_required_structure_cannot_map() {
    let pattern = graph(&[1, 2, 3, 4], &[[1, 2], [3, 4]]);
    let target = graph(&[10, 20, 30, 40], &[[10, 20]]);

    assert!(!contains_subgraph(&pattern, &target));
}

#[test]
fn returned_mapping_uses_internal_vertex_indices() {
    let pattern = graph(&[7, 8], &[[7, 8]]);
    let target = graph(&[70, 80], &[[70, 80]]);

    assert_eq!(
        find_subgraph_mapping(&pattern, &target),
        Some(vec![(0, 0), (1, 1)])
    );
}
