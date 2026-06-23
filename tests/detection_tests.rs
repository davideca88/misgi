use misgi::detection::{analyze_match_from_graph_json, MisgiError};

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
fn does_not_reduce_target_before_matching() {
    let malware = r#"{"vertices":[1,2,3],"edges":[[1,2],[2,3],[3,1]]}"#;
    let target = r#"{"vertices":[10,20,30],"edges":[[10,20],[20,30],[30,10]]}"#;

    let report = analyze_match_from_graph_json(target, malware).expect("graphs should be valid");

    assert!(!report.detected);
    assert_eq!(report.pattern.vertices, 1);
    assert_eq!(report.pattern.edges, 1);
    assert_eq!(report.target.vertices, 3);
    assert_eq!(report.target.edges, 3);
    assert_eq!(report.mapping, None);
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
