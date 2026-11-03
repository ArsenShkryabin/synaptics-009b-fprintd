//! Gallery-side prepared templates — parse once, reuse neighbor contexts across frames.
//!
//! Live Identify used to re-`from_blob` every gallery entry every frame and rebuild
//! [`MinutiaNeighbors`] inside every probe-minutia loop iteration. Gallery geometry is stable
//! between `TemplateSet` edits, so the distance-sorted neighbor lists (and optional descriptor
//! grids at a given W×H) are cached here, keyed by blob digest.
//!
//! Neighbor near/far split uses [`Template::split`] (DLL class-0 / `min[+0xc]`), not `n/2`
//! — see [`docs/qm/matcher-ghidra-pseudocode.md`](../../../docs/qm/matcher-ghidra-pseudocode.md) §1.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, OnceLock};

use crate::geometry_features::{descriptor_grid_init, NeighborMin};
use crate::neighbor::MinutiaNeighbors;
use crate::template::{Minutia, Template, TemplateError};
use crate::enroll::EnrolledTemplate;

/// FNV-ish digest of an opaque enrollment blob — cache key only, not a crypto hash.
pub fn blob_digest(blob: &[u8]) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    blob.hash(&mut h);
    h.finish()
}

fn to_neighbor_min(m: &Minutia) -> NeighborMin {
    NeighborMin {
        x: m.x as i32,
        y: m.y as i32,
        angle: m.angle_deg as u8,
        desc: m.descriptor,
    }
}

/// Cached descriptor grids: `(width, height, per-gallery-minutia grid bytes)`, rebuilt on dim change.
type DescriptorGrids = Option<(u8, u8, Vec<Vec<u8>>)>;

/// One gallery view with precomputed per-minutia neighbor contexts.
#[derive(Debug)]
pub struct PreparedView {
    pub template: Template,
    /// Distance-sorted neighbor indices for each gallery minutia; `primary_count` = `template.split`.
    pub neighbors: Vec<MinutiaNeighbors>,
    /// Neighbor minutiae records matching [`Self::neighbors`] order (for `neighbor_compare`).
    pub neighbor_mins: Vec<Vec<NeighborMin>>,
    /// Descriptor grids at `(w, h)` — one per gallery minutia; rebuilt when dims change.
    grids: Mutex<DescriptorGrids>,
}

impl PreparedView {
    /// Build neighbor contexts for every minutia of `template`.
    pub fn from_template(template: Template) -> Self {
        let n = template.minutiae.len();
        let split = template.split;
        let mut neighbors = Vec::with_capacity(n);
        let mut neighbor_mins = Vec::with_capacity(n);
        for i in 0..n {
            let ctx = MinutiaNeighbors::from_all(&template.minutiae, i, split);
            let mins: Vec<NeighborMin> = ctx
                .indices
                .iter()
                .map(|&idx| to_neighbor_min(&template.minutiae[idx as usize]))
                .collect();
            neighbors.push(ctx);
            neighbor_mins.push(mins);
        }
        Self {
            template,
            neighbors,
            neighbor_mins,
            grids: Mutex::new(None),
        }
    }

    /// Ensure per-minutia descriptor grids exist for `(w, h)`; return a clone of the grid for `gi`.
    pub fn descriptor_grid(&self, gi: usize, w: u8, h: u8) -> Vec<u8> {
        let mut guard = self.grids.lock().unwrap_or_else(|e| e.into_inner());
        let need_rebuild = match &*guard {
            Some((cw, ch, grids)) => *cw != w || *ch != h || grids.len() != self.neighbor_mins.len(),
            None => true,
        };
        if need_rebuild {
            let mut grids = Vec::with_capacity(self.neighbor_mins.len());
            for mins in &self.neighbor_mins {
                let pos: Vec<(i32, i32)> = mins.iter().map(|m| (m.x, m.y)).collect();
                let mut grid = vec![0u8; w as usize * h as usize];
                descriptor_grid_init(&mut grid, w, h, &pos);
                grids.push(grid);
            }
            *guard = Some((w, h, grids));
        }
        guard
            .as_ref()
            .and_then(|(_, _, grids)| grids.get(gi).cloned())
            .unwrap_or_else(|| vec![0xff; w as usize * h as usize])
    }
}

/// Parsed multi-view enrollment with every view pre-prepared.
#[derive(Debug)]
pub struct PreparedEnrolled {
    pub views: Vec<PreparedView>,
}

impl PreparedEnrolled {
    pub fn from_enrolled(enrolled: &EnrolledTemplate) -> Self {
        Self {
            views: enrolled
                .views
                .iter()
                .cloned()
                .map(PreparedView::from_template)
                .collect(),
        }
    }

    pub fn from_blob(blob: &[u8]) -> Result<Self, TemplateError> {
        let enrolled = EnrolledTemplate::from_blob(blob)?;
        Ok(Self::from_enrolled(&enrolled))
    }
}

fn global_cache() -> &'static Mutex<HashMap<u64, Arc<PreparedEnrolled>>> {
    static CACHE: OnceLock<Mutex<HashMap<u64, Arc<PreparedEnrolled>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Return a cached [`PreparedEnrolled`] for `blob`, parsing on first sight.
pub fn prepared_enrolled_cached(blob: &[u8]) -> Result<Arc<PreparedEnrolled>, TemplateError> {
    let dig = blob_digest(blob);
    {
        let guard = global_cache().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(hit) = guard.get(&dig) {
            return Ok(Arc::clone(hit));
        }
    }
    let prepared = Arc::new(PreparedEnrolled::from_blob(blob)?);
    let mut guard = global_cache().lock().unwrap_or_else(|e| e.into_inner());
    // Another thread may have inserted while we parsed.
    Ok(Arc::clone(guard.entry(dig).or_insert_with(|| Arc::clone(&prepared))))
}

/// Empty the process-wide gallery cache (tests / gallery wipe).
pub fn clear_prepared_cache() {
    global_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

/// Precompute probe-side neighbor contexts once per diagnose (probe changes every frame).
pub fn prepare_probe_neighbors(probe: &Template) -> Vec<MinutiaNeighbors> {
    let split = probe.split;
    (0..probe.minutiae.len())
        .map(|i| MinutiaNeighbors::from_all(&probe.minutiae, i, split))
        .collect()
}

/// NeighborMin lists for each probe minutia (mirrors gallery [`PreparedView::neighbor_mins`]).
pub fn prepare_probe_neighbor_mins(
    probe: &Template,
    neighbors: &[MinutiaNeighbors],
) -> Vec<Vec<NeighborMin>> {
    neighbors
        .iter()
        .map(|ctx| {
            ctx.indices
                .iter()
                .map(|&idx| to_neighbor_min(&probe.minutiae[idx as usize]))
                .collect()
        })
        .collect()
}
