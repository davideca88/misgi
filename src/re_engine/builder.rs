use std::collections::{BTreeSet, HashMap, HashSet};

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub address: u64,
    pub esil: String,
}

impl Instruction {
    pub fn new(address: u64, esil: impl Into<String>) -> Self {
        Self {
            address,
            esil: esil.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TrackedElement {
    Register(&'static str),
}

#[derive(Debug, Clone, Default)]
struct EsilValue {
    elements: HashSet<TrackedElement>,
}

impl EsilValue {
    fn from_register(register: &'static str) -> Self {
        Self {
            elements: HashSet::from([TrackedElement::Register(register)]),
        }
    }

    fn merge(values: &[Self]) -> Self {
        let mut elements = HashSet::new();

        for value in values {
            elements.extend(value.elements.iter().copied());
        }

        Self { elements }
    }
}

#[derive(Debug, Default)]
struct InstructionAccess {
    reads: HashSet<TrackedElement>,
    writes: HashSet<TrackedElement>,
}

#[derive(Debug, Serialize)]
struct JsonGraph {
    vertices: Vec<u64>,
    edges: Vec<[u64; 2]>,
}

pub fn build_dependency_graph_json(instructions: &[Instruction]) -> String {
    let graph = build_dependency_graph(instructions);
    serde_json::to_string(&graph).expect("serializing the generated graph should not fail")
}

fn build_dependency_graph(instructions: &[Instruction]) -> JsonGraph {
    let mut vertices = Vec::new();
    let mut seen_vertices = HashSet::new();
    let mut edges = BTreeSet::new();
    let mut last_writer_by_element: HashMap<TrackedElement, u64> = HashMap::new();

    for instruction in instructions {
        if seen_vertices.insert(instruction.address) {
            vertices.push(instruction.address);
        }

        let access = analyze_esil_accesses(&instruction.esil);

        // A register read depends on the most recent instruction that wrote the register.
        for element in &access.reads {
            if let Some(writer) = last_writer_by_element.get(element) {
                edges.insert([*writer, instruction.address]);
            }
        }

        // Overwriting a register also depends on the previous definition of that register.
        // This keeps write-after-write relationships visible in the first graph semantics.
        for element in &access.writes {
            if let Some(writer) = last_writer_by_element.get(element) {
                edges.insert([*writer, instruction.address]);
            }
        }

        for element in access.writes {
            last_writer_by_element.insert(element, instruction.address);
        }
    }

    JsonGraph {
        vertices,
        edges: edges.into_iter().collect(),
    }
}

fn analyze_esil_accesses(esil: &str) -> InstructionAccess {
    let mut stack = Vec::new();
    let mut access = InstructionAccess::default();

    for token in esil
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        match token {
            "=" | ":=" => apply_assignment(&mut stack, &mut access, false),
            "+=" | "-=" | "*=" | "/=" | "%=" | "&=" | "|=" | "^=" => {
                apply_assignment(&mut stack, &mut access, true)
            }
            "+" | "-" | "*" | "/" | "%" | "&" | "|" | "^" | "==" | "<" | ">" | "<=" | ">="
            | "<<" | ">>" => apply_binary_operator(&mut stack),
            "!" | "~" => apply_unary_operator(&mut stack),
            _ if is_memory_write(token) => apply_memory_write(&mut stack, &mut access),
            _ if is_memory_read(token) => apply_memory_read(&mut stack, &mut access),
            _ if is_control_or_flag_token(token) => {}
            _ => stack.push(value_from_token(token)),
        }
    }

    access
}

fn apply_assignment(stack: &mut Vec<EsilValue>, access: &mut InstructionAccess, compound: bool) {
    let destination = stack.pop().unwrap_or_default();
    let source = stack.pop().unwrap_or_default();

    access.reads.extend(source.elements.iter().copied());

    if compound {
        access.reads.extend(destination.elements.iter().copied());
    }

    access.writes.extend(destination.elements.iter().copied());
}

fn apply_binary_operator(stack: &mut Vec<EsilValue>) {
    let right = stack.pop().unwrap_or_default();
    let left = stack.pop().unwrap_or_default();
    stack.push(EsilValue::merge(&[left, right]));
}

fn apply_unary_operator(stack: &mut Vec<EsilValue>) {
    let value = stack.pop().unwrap_or_default();
    stack.push(value);
}

fn apply_memory_read(stack: &mut Vec<EsilValue>, access: &mut InstructionAccess) {
    let address = stack.pop().unwrap_or_default();

    // Memory is not tracked as a data element yet, but computing the address reads registers.
    access.reads.extend(address.elements.iter().copied());
    stack.push(address);
}

fn apply_memory_write(stack: &mut Vec<EsilValue>, access: &mut InstructionAccess) {
    let address = stack.pop().unwrap_or_default();
    let value = stack.pop().unwrap_or_default();

    // The current graph only tracks registers, so memory stores read their value and address.
    access.reads.extend(address.elements.iter().copied());
    access.reads.extend(value.elements.iter().copied());
}

fn value_from_token(token: &str) -> EsilValue {
    canonical_register(token)
        .map(EsilValue::from_register)
        .unwrap_or_default()
}

fn is_memory_read(token: &str) -> bool {
    token.starts_with('[') && token.ends_with(']')
}

fn is_memory_write(token: &str) -> bool {
    token.starts_with("=[") && token.ends_with(']')
}

fn is_control_or_flag_token(token: &str) -> bool {
    token.starts_with('$') || matches!(token, "?{" | "}" | "}{" | "BREAK" | "GOTO")
}

fn canonical_register(token: &str) -> Option<&'static str> {
    match token.to_ascii_lowercase().as_str() {
        "rax" | "eax" | "ax" | "al" | "ah" => Some("rax"),
        "rbx" | "ebx" | "bx" | "bl" | "bh" => Some("rbx"),
        "rcx" | "ecx" | "cx" | "cl" | "ch" => Some("rcx"),
        "rdx" | "edx" | "dx" | "dl" | "dh" => Some("rdx"),
        "rsi" | "esi" | "si" | "sil" => Some("rsi"),
        "rdi" | "edi" | "di" | "dil" => Some("rdi"),
        "rbp" | "ebp" | "bp" | "bpl" => Some("rbp"),
        "rsp" | "esp" | "sp" | "spl" => Some("rsp"),
        "rip" | "eip" | "ip" => Some("rip"),
        "r8" | "r8d" | "r8w" | "r8b" => Some("r8"),
        "r9" | "r9d" | "r9w" | "r9b" => Some("r9"),
        "r10" | "r10d" | "r10w" | "r10b" => Some("r10"),
        "r11" | "r11d" | "r11w" | "r11b" => Some("r11"),
        "r12" | "r12d" | "r12w" | "r12b" => Some("r12"),
        "r13" | "r13d" | "r13w" | "r13b" => Some("r13"),
        "r14" | "r14d" | "r14w" | "r14b" => Some("r14"),
        "r15" | "r15d" | "r15w" | "r15b" => Some("r15"),
        "zf" => Some("zf"),
        "cf" => Some("cf"),
        "sf" => Some("sf"),
        "of" => Some("of"),
        "pf" => Some("pf"),
        "af" => Some("af"),
        _ => None,
    }
}
