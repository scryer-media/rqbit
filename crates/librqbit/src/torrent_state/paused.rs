use std::{collections::HashSet, sync::Arc};

use librqbit_core::lengths::ValidPieceIndex;

use crate::{
    chunk_tracker::{ChunkTracker, HaveNeededSelected},
    piece_priority::PiecePriority,
    type_aliases::FileStorage,
};

use super::{ManagedTorrentShared, TorrentMetadata, streaming::TorrentStreams};

pub struct TorrentStatePaused {
    pub(crate) shared: Arc<ManagedTorrentShared>,
    pub(crate) metadata: Arc<TorrentMetadata>,
    pub(crate) files: FileStorage,
    pub(crate) chunk_tracker: ChunkTracker,
    pub(crate) streams: Arc<TorrentStreams>,
}

impl TorrentStatePaused {
    pub(crate) fn update_only_files(&mut self, only_files: &HashSet<usize>) -> anyhow::Result<()> {
        self.chunk_tracker
            .update_only_files(&self.metadata.file_infos, only_files)?;
        Ok(())
    }

    pub(crate) fn set_piece_priorities(
        &mut self,
        priorities: impl IntoIterator<Item = (ValidPieceIndex, PiecePriority)>,
    ) {
        self.chunk_tracker.set_piece_priorities(priorities);
    }

    pub(crate) fn hns(&self) -> &HaveNeededSelected {
        self.chunk_tracker.get_hns()
    }
}
