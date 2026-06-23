use misgi::graph_export::{export_graph, GraphExportFormat};
use misgi::graph_processor::GraphModel;

fn sample_graph() -> GraphModel {
    GraphModel::from_json(r#"{"vertices":[1,2,3],"edges":[[1,2],[2,3]]}"#)
        .expect("sample graph should be valid")
}

#[test]
fn exports_json_graph() {
    let exported = export_graph(&sample_graph(), GraphExportFormat::Json);

    assert_eq!(
        exported,
        "{\n  \"vertices\": [\n    0,\n    1,\n    2\n  ],\n  \"edges\": [\n    [\n      0,\n      1\n    ],\n    [\n      1,\n      2\n    ]\n  ]\n}"
    );
}

#[test]
fn exports_dot_graph() {
    let exported = export_graph(&sample_graph(), GraphExportFormat::Dot);

    assert_eq!(
        exported,
        "digraph misgi {\n    0;\n    1;\n    2;\n    0 -> 1;\n    1 -> 2;\n}\n"
    );
}

#[test]
fn exports_gml_graph() {
    let exported = export_graph(&sample_graph(), GraphExportFormat::Gml);

    assert_eq!(
        exported,
        "graph [\n    directed 1\n    node [ id 0 ]\n    node [ id 1 ]\n    node [ id 2 ]\n    edge [ source 0 target 1 ]\n    edge [ source 1 target 2 ]\n]\n"
    );
}
