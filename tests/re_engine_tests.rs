use misgi::graph_processor::GraphModel;
use misgi::re_engine::{build_dependency_graph_json, Instruction};

fn graph_from_instructions(instructions: Vec<Instruction>) -> GraphModel {
    let json = build_dependency_graph_json(&instructions);
    GraphModel::from_json(&json).expect("generated JSON should parse as a graph model")
}

#[test]
fn single_write_creates_vertex_without_edges() {
    let graph = graph_from_instructions(vec![Instruction::new(10, "1,rax,=")]);

    assert_eq!(graph.vertex_count(), 1);
    assert_eq!(graph.edge_count(), 0);
}

#[test]
fn register_read_depends_on_previous_write() {
    let graph = graph_from_instructions(vec![
        Instruction::new(10, "1,rax,="),
        Instruction::new(20, "rax,rbx,="),
    ]);

    assert!(graph.has_edge_by_index(0, 1));
}

#[test]
fn register_overwrite_depends_on_previous_write() {
    let graph = graph_from_instructions(vec![
        Instruction::new(10, "1,rax,="),
        Instruction::new(20, "2,rax,="),
    ]);

    assert!(graph.has_edge_by_index(0, 1));
}

#[test]
fn compound_assignment_reads_destination_register() {
    let graph = graph_from_instructions(vec![
        Instruction::new(10, "1,rsp,="),
        Instruction::new(20, "8,rsp,-="),
    ]);

    assert!(graph.has_edge_by_index(0, 1));
}

#[test]
fn register_aliases_use_the_same_tracked_element() {
    let graph = graph_from_instructions(vec![
        Instruction::new(10, "1,rax,="),
        Instruction::new(20, "eax,rbx,="),
    ]);

    assert!(graph.has_edge_by_index(0, 1));
}

#[test]
fn repeated_register_reads_create_one_logical_edge() {
    let graph = graph_from_instructions(vec![
        Instruction::new(10, "1,rax,="),
        Instruction::new(20, "rax,rax,+,rbx,="),
    ]);

    assert!(graph.has_edge_by_index(0, 1));
    assert_eq!(graph.edge_count(), 1);
}

#[test]
fn memory_read_uses_address_registers_but_does_not_track_memory() {
    let graph = graph_from_instructions(vec![
        Instruction::new(10, "1,rbp,="),
        Instruction::new(20, "0x8,rbp,-,[8],rax,="),
    ]);

    assert!(graph.has_edge_by_index(0, 1));
}

#[test]
fn unknown_esil_still_creates_vertices() {
    let graph = graph_from_instructions(vec![
        Instruction::new(10, ""),
        Instruction::new(20, "unknown-token"),
    ]);

    assert_eq!(graph.vertex_count(), 2);
    assert_eq!(graph.edge_count(), 0);
}
