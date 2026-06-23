use crate::graph_processor::model::GraphModel;

pub fn contains_subgraph(pattern: &GraphModel, target: &GraphModel) -> bool {
    find_subgraph_mapping(pattern, target).is_some()
}

pub fn find_subgraph_mapping(
    pattern: &GraphModel,
    target: &GraphModel,
) -> Option<Vec<(usize, usize)>> {
    if pattern.vertex_count() > target.vertex_count() {
        return None;
    }

    if pattern.vertex_count() == 0 {
        return Some(Vec::new());
    }

    let compatibility = build_compatibility_matrix(pattern, target);
    let mut mapping = vec![None; pattern.vertex_count()];
    let mut used_targets = vec![false; target.vertex_count()];

    if search(
        0,
        pattern,
        target,
        &compatibility,
        &mut mapping,
        &mut used_targets,
    ) {
        return Some(mapping_to_internal_indices(&mapping));
    }

    None
}

fn build_compatibility_matrix(pattern: &GraphModel, target: &GraphModel) -> Vec<Vec<bool>> {
    let mut matrix = vec![vec![false; target.vertex_count()]; pattern.vertex_count()];

    for (pattern_index, row) in matrix.iter_mut().enumerate() {
        for (target_index, cell) in row.iter_mut().enumerate() {
            // The compatibility matrix is Ullmann's first pruning step:
            // rows are pattern vertices, columns are target vertices, and a
            // true cell means the target vertex can still represent that
            // pattern vertex before recursion starts.
            //
            // Degree pruning is valid for non-induced matching because every
            // incoming/outgoing pattern edge must be preserved in the target.
            // A target vertex with fewer directed neighbors cannot preserve
            // all required edges for the pattern vertex.
            *cell = pattern.out_degree(pattern_index) <= target.out_degree(target_index)
                && pattern.in_degree(pattern_index) <= target.in_degree(target_index);
        }
    }

    matrix
}

fn search(
    pattern_index: usize,
    pattern: &GraphModel,
    target: &GraphModel,
    compatibility: &[Vec<bool>],
    mapping: &mut [Option<usize>],
    used_targets: &mut [bool],
) -> bool {
    if pattern_index == pattern.vertex_count() {
        return true;
    }

    for target_index in 0..target.vertex_count() {
        if !compatibility[pattern_index][target_index] || used_targets[target_index] {
            continue;
        }

        // Each target vertex can be used at most once, so the mapping is
        // injective. Recursion assigns one pattern row at a time; backtracking
        // clears the assignment when a later row cannot be matched.
        mapping[pattern_index] = Some(target_index);
        used_targets[target_index] = true;

        if preserves_mapped_edges(pattern_index, pattern, target, mapping)
            && search(
                pattern_index + 1,
                pattern,
                target,
                compatibility,
                mapping,
                used_targets,
            )
        {
            return true;
        }

        used_targets[target_index] = false;
        mapping[pattern_index] = None;
    }

    false
}

fn preserves_mapped_edges(
    current_pattern_index: usize,
    pattern: &GraphModel,
    target: &GraphModel,
    mapping: &[Option<usize>],
) -> bool {
    let current_target_index = mapping[current_pattern_index]
        .expect("current pattern vertex must be assigned before edge checks");

    for (other_pattern_index, other_target_index) in mapping.iter().enumerate() {
        let Some(other_target_index) = other_target_index else {
            continue;
        };

        // This is the directed edge-preservation check. Every pattern edge
        // involving the newly mapped vertex must exist in the same direction
        // between the mapped target vertices.
        if pattern.has_edge_by_index(current_pattern_index, other_pattern_index)
            && !target.has_edge_by_index(current_target_index, *other_target_index)
        {
            return false;
        }

        if pattern.has_edge_by_index(other_pattern_index, current_pattern_index)
            && !target.has_edge_by_index(*other_target_index, current_target_index)
        {
            return false;
        }
    }

    // Extra target edges are intentionally ignored. That is the difference
    // between this non-induced matcher and an induced subgraph matcher.
    true
}

fn mapping_to_internal_indices(mapping: &[Option<usize>]) -> Vec<(usize, usize)> {
    mapping
        .iter()
        .enumerate()
        .map(|(pattern_index, target_index)| {
            (
                pattern_index,
                target_index.expect("complete mapping should not contain gaps"),
            )
        })
        .collect()
}
