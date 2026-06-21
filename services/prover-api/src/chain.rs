//! Chain-state helpers: fetch commitment/leaf events and reconstruct Merkle trees.
//!
//! Soroban's `getEvents` scans only a bounded window (~10k ledgers) per call and
//! returns a `cursor` to continue. A single call from the pool's deployment ledger
//! will frequently return ZERO events (the window predates the first deposit) yet
//! still hand back a valid cursor pointing further forward. Callers MUST page with
//! that cursor until the cursor's ledger reaches the events tip (`latest_ledger`),
//! NOT stop on the first empty page. Stopping early silently truncates the
//! commitment set and produces "leaf index out of range" failures downstream.

use anyhow::{Result, anyhow};
use state::events_parsers::parse_event;
use stellar::Client;
use types::{Field, ProcessedEvent};

const PAGE_SIZE: usize = 300;
/// Hard safety cap on pages to walk in a single fetch. At ~10k ledgers/page this
/// covers ~20M ledgers (years of testnet), far beyond any real retention window.
const MAX_PAGES: usize = 2048;

/// Decode the ledger sequence encoded in a Soroban events cursor.
///
/// The cursor is `"{toid}-{opindex}"` where `toid` is a zero-padded decimal u64
/// laid out as `(ledger << 32) | (tx_index << 12) | op_index`. The ledger is the
/// high 32 bits. Returns `None` if the cursor is empty or unparseable.
fn cursor_ledger(cursor: &str) -> Option<u64> {
    let toid_str = cursor.split('-').next()?;
    let toid: u64 = toid_str.trim().parse().ok()?;
    Some(toid >> 32)
}

/// Fetch all pool `NewCommitmentEvent`s starting from `from_ledger`.
/// Returns a list of `(index, commitment)` sorted by ascending index.
pub async fn fetch_pool_commitments(
    client: &Client,
    pool_id: &str,
    from_ledger: u32,
) -> Result<Vec<(u32, Field)>> {
    let mut all: Vec<(u32, Field)> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0usize;
    let mut total_events = 0usize;

    loop {
        let (next_cursor, events, latest) = client
            .get_contract_events(
                &[pool_id.to_string()],
                from_ledger,
                PAGE_SIZE,
                cursor.clone(),
            )
            .await
            .map_err(|e| {
                anyhow!("get_contract_events(pool) page={pages} cursor={cursor:?}: {e}")
            })?;

        let page_event_count = events.len();
        total_events += page_event_count;
        let mut page_commitments = 0usize;
        for ev in events {
            let contract_event: types::ContractEvent = ev.into();
            match parse_event(contract_event) {
                Ok(ProcessedEvent::Commitment(c)) => {
                    all.push((c.index, c.commitment));
                    page_commitments += 1;
                }
                _ => {}
            }
        }

        let cur_ledger = next_cursor.as_deref().and_then(cursor_ledger);
        tracing::debug!(
            "[fetch_pool_commitments] page={pages} events={page_event_count} \
             commitments+={page_commitments} total_commitments={} cursor_ledger={cur_ledger:?} latest_ledger={latest}",
            all.len()
        );

        pages += 1;
        if pages >= MAX_PAGES {
            tracing::warn!("[fetch_pool_commitments] hit MAX_PAGES={MAX_PAGES}; stopping");
            break;
        }

        // Continue paging while the cursor has not yet reached the events tip.
        // An empty page is NOT a stop signal — intermediate windows can be empty.
        match (&next_cursor, cur_ledger) {
            (Some(c), Some(cl)) if !c.is_empty() && cl < latest as u64 => {
                cursor = Some(c.clone());
            }
            _ => break,
        }
    }

    all.sort_by_key(|(idx, _)| *idx);
    tracing::info!(
        "[fetch_pool_commitments] done: {} commitments across {pages} pages ({total_events} raw events) from_ledger={from_ledger}",
        all.len()
    );
    Ok(all)
}

/// Fetch all ASP membership `LeafAdded` events from `from_ledger`.
/// Returns leaf values sorted by ascending index.
pub async fn fetch_asp_membership_leaves(
    client: &Client,
    asp_membership_id: &str,
    from_ledger: u32,
) -> Result<Vec<Field>> {
    let mut all: Vec<(u32, Field)> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0usize;

    loop {
        let (next_cursor, events, latest) = client
            .get_contract_events(
                &[asp_membership_id.to_string()],
                from_ledger,
                PAGE_SIZE,
                cursor.clone(),
            )
            .await
            .map_err(|e| {
                anyhow!("get_contract_events(asp_membership) page={pages} cursor={cursor:?}: {e}")
            })?;

        let page_event_count = events.len();
        for ev in events {
            let contract_event: types::ContractEvent = ev.into();
            match parse_event(contract_event) {
                Ok(ProcessedEvent::LeafAdded(l)) => {
                    all.push((l.index, l.leaf));
                }
                _ => {}
            }
        }

        let cur_ledger = next_cursor.as_deref().and_then(cursor_ledger);
        tracing::debug!(
            "[fetch_asp_membership_leaves] page={pages} events={page_event_count} \
             total_leaves={} cursor_ledger={cur_ledger:?} latest_ledger={latest}",
            all.len()
        );

        pages += 1;
        if pages >= MAX_PAGES {
            tracing::warn!("[fetch_asp_membership_leaves] hit MAX_PAGES={MAX_PAGES}; stopping");
            break;
        }

        match (&next_cursor, cur_ledger) {
            (Some(c), Some(cl)) if !c.is_empty() && cl < latest as u64 => {
                cursor = Some(c.clone());
            }
            _ => break,
        }
    }

    all.sort_by_key(|(idx, _)| *idx);
    tracing::info!(
        "[fetch_asp_membership_leaves] done: {} leaves across {pages} pages from_ledger={from_ledger}",
        all.len()
    );
    Ok(all.into_iter().map(|(_, leaf)| leaf).collect())
}
