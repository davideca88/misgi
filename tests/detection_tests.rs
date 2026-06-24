use misgi::detection::{
    analyze_detection_with_mock_from_graph_json, analyze_match_from_graph_json, MisgiError,
};
use misgi::graph_processor::mock::MockConfig;

#[test]
fn detects_malware_graph_inside_target_graph() {
    let malware = r#"{"vertices":[1,2],"edges":[[1,2]]}"#;
    let target = r#"{"vertices":[10,20,30],"edges":[[10,20],[20,30]]}"#;

    let report = analyze_match_from_graph_json(target, malware).expect("graphs should be valid");

    assert!(report.detected);
    assert_eq!(report.pattern.vertices, 2);
    assert_eq!(report.pattern.edges, 1);
    assert_eq!(report.target.vertices, 3);
    assert_eq!(report.target.edges, 2);
    assert!(report.mapping.is_some());
}

#[test]
fn reports_no_match_when_pattern_edge_is_missing() {
    let malware = r#"{"vertices":[1,2],"edges":[[1,2]]}"#;
    let target = r#"{"vertices":[10,20],"edges":[]}"#;

    let report = analyze_match_from_graph_json(target, malware).expect("graphs should be valid");

    assert!(!report.detected);
    assert_eq!(report.mapping, None);
}

#[test]
fn falls_back_to_original_pattern_when_reduction_erases_it() {
    let malware = r#"{"vertices":[1,2,3],"edges":[[1,2],[2,3]]}"#;
    let target = r#"{"vertices":[10,20],"edges":[[10,20]]}"#;

    let report = analyze_match_from_graph_json(target, malware).expect("graphs should be valid");

    assert!(!report.detected);
    assert_eq!(report.pattern.vertices, 3);
    assert_eq!(report.pattern.edges, 2);
    assert_eq!(report.mapping, None);
}

#[test]
fn uses_reduced_pattern_when_reduction_keeps_signature_non_empty() {
    let malware = r#"{"vertices":[1,2,3],"edges":[[1,2],[2,3],[3,1]]}"#;
    let target = r#"{"vertices":[10],"edges":[[10,10]]}"#;

    let report = analyze_match_from_graph_json(target, malware).expect("graphs should be valid");

    assert!(report.detected);
    assert_eq!(report.pattern.vertices, 1);
    assert_eq!(report.pattern.edges, 1);
    assert_eq!(report.target.vertices, 1);
    assert_eq!(report.target.edges, 1);
    assert!(report.mapping.is_some());
}

#[test]
fn invalid_malware_graph_returns_contextual_error() {
    let malware = r#"{"vertices":[1,1],"edges":[]}"#;
    let target = r#"{"vertices":[10],"edges":[]}"#;

    let error =
        analyze_match_from_graph_json(target, malware).expect_err("duplicate vertex should fail");

    assert!(matches!(error, MisgiError::MalwareGraph(_)));
}

#[test]
fn invalid_target_graph_returns_contextual_error() {
    let malware = r#"{"vertices":[1],"edges":[]}"#;
    let target = r#"{"vertices":[10],"edges":[[10,20]]}"#;

    let error =
        analyze_match_from_graph_json(target, malware).expect_err("missing vertex should fail");

    assert!(matches!(error, MisgiError::TargetGraph(_)));
}

#[test]
fn mock_detection_injects_pattern_after_reduction() {
    let malware = r#"{"vertices":[1,2],"edges":[[1,2]]}"#;
    let target = r#"{"vertices":[10,20],"edges":[]}"#;
    let config = MockConfig {
        perturbation_percentage: 0.0,
        add_ratio: 0.5,
        seed: 7,
    };

    let analysis = analyze_detection_with_mock_from_graph_json(target, malware, &config)
        .expect("mock injection should succeed");

    assert!(analysis.report.detected);
    assert_eq!(analysis.report.pattern.vertices, 2);
    assert_eq!(analysis.report.pattern.edges, 1);
    assert_eq!(analysis.report.target.vertices, 2);
    assert_eq!(analysis.report.target.edges, 1);
    assert_eq!(analysis.original_target_graph.edge_count(), 0);
    assert_eq!(analysis.target_mock_graph.edge_count(), 1);
    assert_eq!(analysis.mock_report.edges_added_for_perturbation, 0);
    assert_eq!(analysis.mock_report.edges_removed_for_perturbation, 0);
}
