use misgi::graph_processor::{GraphModel, GraphModelError};

#[test]
fn valid_json_graph_parses_successfully() {
    let graph = GraphModel::from_json(
        r#"{
            "vertices": [1, 2, 3],
            "edges": [[1, 2], [2, 3]]
        }"#,
    )
    .expect("valid graph should parse");

    assert_eq!(graph.vertex_count(), 3);
    assert_eq!(graph.edge_count(), 2);
    assert!(graph.has_edge_by_index(0, 1));
    assert!(graph.has_edge_by_index(1, 2));
}

#[test]
fn duplicate_vertices_fail() {
    let error = GraphModel::from_json(
        r#"{
            "vertices": [1, 2, 1],
            "edges": []
        }"#,
    )
    .expect_err("duplicate vertex should fail");

    assert!(matches!(error, GraphModelError::DuplicateVertex(1)));
}

#[test]
fn edge_with_missing_source_fails() {
    let error = GraphModel::from_json(
        r#"{
            "vertices": [1, 2],
            "edges": [[3, 2]]
        }"#,
    )
    .expect_err("missing source should fail");

    assert!(matches!(error, GraphModelError::MissingSourceVertex(3)));
}

#[test]
fn edge_with_missing_target_fails() {
    let error = GraphModel::from_json(
        r#"{
            "vertices": [1, 2],
            "edges": [[1, 3]]
        }"#,
    )
    .expect_err("missing target should fail");

    assert!(matches!(error, GraphModelError::MissingTargetVertex(3)));
}

#[test]
fn duplicate_edges_behave_as_one_logical_edge() {
    let graph = GraphModel::from_json(
        r#"{
            "vertices": [1, 2],
            "edges": [[1, 2], [1, 2]]
        }"#,
    )
    .expect("duplicate edges should be accepted");

    assert_eq!(graph.edge_count(), 1);
    assert!(graph.has_edge_by_index(0, 1));
}

#[test]
fn self_loop_is_accepted() {
    let graph = GraphModel::from_json(
        r#"{
            "vertices": [1],
            "edges": [[1, 1]]
        }"#,
    )
    .expect("self-loop should be accepted");

    assert_eq!(graph.vertex_count(), 1);
    assert_eq!(graph.edge_count(), 1);
    assert!(graph.has_edge_by_index(0, 0));
}

#[test]
fn malformed_edge_pair_fails_during_json_parsing() {
    let error = GraphModel::from_json(
        r#"{
            "vertices": [1, 2],
            "edges": [[1, 2, 3]]
        }"#,
    )
    .expect_err("malformed edge pair should fail");

    assert!(matches!(error, GraphModelError::InvalidJson(_)));
}
