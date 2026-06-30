//! Direct graph-file import, bypassing the binary reverse-engineering step.
//!
//! This module lets the CLI accept JSON or DOT graph files directly (via
//! `-i, --import-graphs`) instead of binaries that would normally be fed
//! through `re_engine`. The resulting [`GraphModel`] is built exactly the
//! way `GraphModel::from_json` builds one from a binary-derived graph, so the
//! rest of the pipeline (matching, `--mock` perturbation, `--export-graphs`)
//! treats an imported graph indistinguishably from a binary-derived one.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use dot_parser::{ast, canonical};
use petgraph::graph::NodeIndex;
use petgraph::{Directed, Graph};
use thiserror::Error;

use crate::detection::MisgiError;
use crate::graph_processor::{GraphModel, GraphModelError};

/// The two file formats `import_graph_model` understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportGraphFormat {
    Json,
    Dot,
}

impl ImportGraphFormat {
    /// Parses a `-F, --import-format` CLI value. Mirrors
    /// `GraphExportFormat::parse`'s style/case-insensitivity.
    pub fn parse(value: &OsStr) -> Option<Self> {
        match value.to_string_lossy().to_ascii_lowercase().as_str() {
            "json" => Some(Self::Json),
            "dot" => Some(Self::Dot),
            _ => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum ImportGraphError {
    #[error("failed to read graph file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "cannot infer graph format for {0} from its extension; pass -F/--import-format json|dot"
    )]
    UnknownFormat(PathBuf),

    #[error("failed to parse JSON graph {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: GraphModelError,
    },

    #[error("failed to parse DOT graph {path}: {err}")]
    Dot { path: PathBuf, err: String },

    #[error("graph detection failed: {0}")]
    Detection(#[from] MisgiError),
}

/// Loads a single graph file (JSON or DOT) into a [`GraphModel`].
///
/// Format resolution is **extension-first, `-F` fallback-only**:
/// - `.json` -> JSON. `.dot` / `.gv` -> DOT. These always win, even if they
///   contradict `format_override`.
/// - `.jsonc` is intentionally *not* matched as JSON (no comment support),
///   so it falls through to the fallback below like any other unknown
///   extension.
/// - Anything else (unknown or missing extension) falls back to
///   `format_override` (the `-F` flag). If that's also `None`, this returns
///   [`ImportGraphError::UnknownFormat`].
pub fn import_graph_model(
    path: &Path,
    format_override: Option<ImportGraphFormat>,
) -> Result<GraphModel, ImportGraphError> {
    let format = resolve_format(path, format_override)?;

    let contents = fs::read_to_string(path).map_err(|source| ImportGraphError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    match format {
        ImportGraphFormat::Json => {
            GraphModel::from_json(&contents).map_err(|source| ImportGraphError::Json {
                path: path.to_path_buf(),
                source,
            })
        }
        ImportGraphFormat::Dot => parse_dot(&contents).map_err(|source| ImportGraphError::Dot {
            path: path.to_path_buf(),
            err: source,
        }),
    }
}

fn resolve_format(
    path: &Path,
    format_override: Option<ImportGraphFormat>,
) -> Result<ImportGraphFormat, ImportGraphError> {
    let extension = path
        .extension()
        .and_then(OsStr::to_str)
        .map(str::to_ascii_lowercase);

    match extension.as_deref() {
        Some("json") => Ok(ImportGraphFormat::Json),
        Some("dot") | Some("gv") => Ok(ImportGraphFormat::Dot),
        // Unknown/missing extension (including ".jsonc", which is
        // deliberately not treated as JSON) falls back to `-F`. A
        // recognized extension above always wins over `-F`, never the
        // reverse.
        _ => format_override.ok_or_else(|| ImportGraphError::UnknownFormat(path.to_path_buf())),
    }
}

/// Parses a DOT source string via petgraph's `dot_parser` feature and maps
/// it into the application's internal `Graph<(), (), Directed>`
/// representation, deduplicating nodes by DOT identifier and deduplicating
/// repeated edges the same way `GraphModel::from_json` does for JSON input.
/// Self-loops are preserved (the JSON path allows them too).
///
/// NOTE: I could not verify petgraph 0.8's exact `dot_parser` entry point in
/// this environment (no network access, and the crate doesn't compile yet
/// regardless, since `detection.rs`, `re_engine.rs`, and
/// `graph_processor::{mock,reduction,ullmann}` are missing from what was
/// shared with me). This assumes the feature implements `FromStr` for
/// `Graph<String, String, Directed>`, which is the documented shape of that
/// feature. If the real 0.8 API differs, the single call below is the only
/// line that should need changing — everything after it operates on a
/// generic `Graph<String, String, Directed>` and is API-agnostic.
/*
fn parse_dot(source: &str) -> Result<GraphModel, String> {
    let parsed: Graph<String, String, Directed> = < AJEITA AQUI >

    let mut external_to_internal: HashMap<String, NodeIndex> = HashMap::with_capacity(parsed.node_count());
    let mut graph = Graph::<(), (), Directed>::new();

    for node in parsed.node_indices() {
        let label = parsed[node].clone();
        external_to_internal
            .entry(label)
            .or_insert_with(|| graph.add_node(()));
    }

    let mut seen_edges = HashSet::new();

    for edge in parsed.edge_indices() {
        let (source_node, target_node) = parsed
            .edge_endpoints(edge)
            .expect("edge index from a freshly parsed graph is always valid");

        let source_index = external_to_internal[&parsed[source_node]];
        let target_index = external_to_internal[&parsed[target_node]];

        if seen_edges.insert((source_index, target_index)) {
            graph.add_edge(source_index, target_index, ());
        }
    }

    Ok(GraphModel { graph })
}
*/

fn parse_dot(source: &str) -> Result<GraphModel, String> {
    // 1. Pipeline inicial: Transforma a String no AST e depois no formato Canônico do dot-parser
    let ast_graph = ast::Graph::try_from(source)
        .map_err(|e| format!("Erro de sintaxe no arquivo DOT: {:?}", e))?;
    let canonical_graph = canonical::Graph::from(ast_graph);

    // 2. Cria e popula a variável `parsed` esperada pelo resto do seu código
    let mut parsed = Graph::<String, String, Directed>::new();
    let mut parsed_nodes = HashMap::new();

    // Insere as arestas e nós conectados
    for edge in canonical_graph.edges.set {
        let from_id = edge.from.to_string();
        let to_id = edge.to.to_string();

        let from_idx = *parsed_nodes
            .entry(from_id.clone())
            .or_insert_with(|| parsed.add_node(from_id));

        let to_idx = *parsed_nodes
            .entry(to_id.clone())
            .or_insert_with(|| parsed.add_node(to_id));

        let edge_weight = format!("{}->{}", edge.from, edge.to);
        parsed.add_edge(from_idx, to_idx, edge_weight);
    }

    // Garante a inclusão de nós que porventura estejam isolados no arquivo DOT
    for (node_id, _node_struct) in canonical_graph.nodes.set {
        parsed_nodes
            .entry(node_id.clone())
            .or_insert_with(|| parsed.add_node(node_id));
    }

    // --- SEU ALGORITMO ORIGINAL DAQUI PARA BAIXO ---

    let mut external_to_internal: HashMap<String, NodeIndex> = HashMap::with_capacity(parsed.node_count());
    let mut graph = Graph::<(), (), Directed>::new();

    for node in parsed.node_indices() {
        let label = parsed[node].clone();
        external_to_internal
            .entry(label)
            .or_insert_with(|| graph.add_node(()));
    }

    let mut seen_edges = HashSet::new();

    for edge in parsed.edge_indices() {
        let (source_node, target_node) = parsed
            .edge_endpoints(edge)
            .expect("edge index from a freshly parsed graph is always valid");

        let source_index = external_to_internal[&parsed[source_node]];
        let target_index = external_to_internal[&parsed[target_node]];

        if seen_edges.insert((source_index, target_index)) {
            graph.add_edge(source_index, target_index, ());
        }
    }

    Ok(GraphModel { graph })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_wins_over_fallback_even_when_contradictory() {
        let path = Path::new("target.json");
        let resolved = resolve_format(path, Some(ImportGraphFormat::Dot)).unwrap();
        assert_eq!(resolved, ImportGraphFormat::Json);
    }

    #[test]
    fn dot_and_gv_extensions_map_to_dot() {
        assert_eq!(
            resolve_format(Path::new("malware.dot"), None).unwrap(),
            ImportGraphFormat::Dot
        );
        assert_eq!(
            resolve_format(Path::new("malware.gv"), None).unwrap(),
            ImportGraphFormat::Dot
        );
    }

    #[test]
    fn jsonc_extension_is_not_treated_as_json() {
        let error = resolve_format(Path::new("target.jsonc"), None).unwrap_err();
        assert!(matches!(error, ImportGraphError::UnknownFormat(_)));
    }

    #[test]
    fn jsonc_extension_uses_fallback_when_provided() {
        let resolved =
            resolve_format(Path::new("target.jsonc"), Some(ImportGraphFormat::Json)).unwrap();
        assert_eq!(resolved, ImportGraphFormat::Json);
    }

    #[test]
    fn unknown_extension_without_fallback_errors() {
        let error = resolve_format(Path::new("target.bin"), None).unwrap_err();
        assert!(matches!(error, ImportGraphError::UnknownFormat(_)));
    }

    #[test]
    fn missing_extension_falls_back() {
        let resolved = resolve_format(Path::new("target"), Some(ImportGraphFormat::Dot)).unwrap();
        assert_eq!(resolved, ImportGraphFormat::Dot);
    }
}
