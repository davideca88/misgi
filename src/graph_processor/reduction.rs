use crate::graph_processor::model::GraphModel;
use petgraph::graph::NodeIndex;
use petgraph::Direction;

/// Made a fully reduce on the graph
///
/// It removes every vertex that matches:
///     1. d(v) = 0
///     2. Has only one exit and no entries
///     3. Has only entry and no exits
///     4. Has only one entry and only one exit
///         u -> v -> w becomes u -> w
///     5. d(v) = 0. Again, because the previous reduction may
///         recrate that condition.
pub fn reduce_fully(model: &mut GraphModel) {
    reduce_isolated(model);
    reduce_one_exit_only(model);
    reduce_one_entry_only(model);
    reduce_connecting_vertices(model);
    reduce_isolated(model);
}

fn remove_node(model: &mut GraphModel, node: NodeIndex) {
    // petgraph::Graph compacts node storage by moving the last node into the
    // removed slot. That reordering is acceptable because GraphModel no longer
    // preserves external vertex IDs after parsing.
    model.graph.remove_node(node);
}

fn degree(model: &GraphModel, node: NodeIndex, direction: Direction) -> usize {
    model.graph.neighbors_directed(node, direction).count()
}

/// If a vertex has exactly one exit edge and no entry edges, it is removed.
pub fn reduce_one_exit_only(model: &mut GraphModel) {
    loop {
        let target = model.graph.node_indices().find(|&node| {
            degree(model, node, Direction::Incoming) == 0
                && degree(model, node, Direction::Outgoing) == 1
        });

        if let Some(node) = target {
            remove_node(model, node);
        } else {
            break;
        }
    }
}

/// If a vertex has exactly one entry edge and no exit edges, it is removed.
pub fn reduce_one_entry_only(model: &mut GraphModel) {
    loop {
        let target = model.graph.node_indices().find(|&node| {
            degree(model, node, Direction::Incoming) == 1
                && degree(model, node, Direction::Outgoing) == 0
        });

        if let Some(node) = target {
            remove_node(model, node);
        } else {
            break;
        }
    }
}

/// If a vertex has exactly one exit and one entry edge, it is removed,
/// and its incoming origin is connected directly to its outgoing destiny.
pub fn reduce_connecting_vertices(model: &mut GraphModel) {
    loop {
        let target_info = model.graph.node_indices().find_map(|node| {
            let mut incoming = model.graph.neighbors_directed(node, Direction::Incoming);
            let mut outgoing = model.graph.neighbors_directed(node, Direction::Outgoing);

            if let (Some(source), None) = (incoming.next(), incoming.next()) {
                if let (Some(target), None) = (outgoing.next(), outgoing.next()) {
                    // Avoid handling self-loops here to prevent unexpected cycles.
                    if source != node && target != node {
                        return Some((node, source, target));
                    }
                }
            }

            None
        });

        if let Some((node, source, target)) = target_info {
            // Bridge the gap: link origin to destiny if the link does not exist yet.
            if model.graph.find_edge(source, target).is_none() {
                model.graph.add_edge(source, target, ());
            }

            remove_node(model, node);
        } else {
            break;
        }
    }
}

/// If a vertex has a total degree of 0, it is removed.
pub fn reduce_isolated(model: &mut GraphModel) {
    loop {
        let target = model.graph.node_indices().find(|&node| {
            degree(model, node, Direction::Incoming) == 0
                && degree(model, node, Direction::Outgoing) == 0
        });

        if let Some(node) = target {
            remove_node(model, node);
        } else {
            break;
        }
    }
}
