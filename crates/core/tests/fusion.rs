//! Fusion de deux versions d'un coffre.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::thread::sleep;
use std::time::Duration;

use common::*;
use keepass::db::fields;
use ligrivsstore_core::{Error, OpenLimits, Vault};

/// Deux copies du même coffre, comme sur deux terminaux.
fn two_copies() -> (Vault, Vault, String) {
    let mut original = Vault::create("Essai", fast_kdf()).unwrap();
    let id = original.add_entry(&entry("Banque", "v1")).unwrap();
    let bytes = original.to_bytes(&key()).unwrap();
    let a = Vault::open(&bytes, &key(), &OpenLimits::default()).unwrap();
    let b = Vault::open(&bytes, &key(), &OpenLimits::default()).unwrap();
    (a, b, id)
}

#[test]
fn additions_on_both_sides_are_kept() {
    let (mut a, mut b, _) = two_copies();
    a.add_entry(&entry("Messagerie", "a")).unwrap();
    b.add_entry(&entry("Impots", "b")).unwrap();
    let report = a.merge_from(&b).unwrap();
    assert_eq!(report.created, 1);
    let titles: Vec<String> = a.entries().into_iter().map(|e| e.title).collect();
    assert_eq!(titles, ["Banque", "Impots", "Messagerie"]);
}

#[test]
fn latest_edit_wins_and_the_other_goes_to_history() {
    let (mut a, mut b, id) = two_copies();
    // Le format est à la seconde : les pauses garantissent l'ordre des versions.
    sleep(Duration::from_millis(1_100));
    a.update_entry(&id, &entry("Banque", "modifié sur A"))
        .unwrap();
    sleep(Duration::from_millis(1_100));
    b.update_entry(&id, &entry("Banque", "modifié sur B, plus tard"))
        .unwrap();

    let mut on_a = a.clone();
    on_a.merge_from(&b).unwrap();
    let mut on_b = b.clone();
    on_b.merge_from(&a).unwrap();
    for merged in [&on_a, &on_b] {
        let details = merged.entry(&id).unwrap();
        assert_eq!(details.password.as_str(), "modifié sur B, plus tard");
        let history: Vec<String> = merged
            .database()
            .entry(keepass::db::EntryId::from_uuid(id.parse().unwrap()))
            .unwrap()
            .history
            .as_ref()
            .unwrap()
            .get_entries()
            .iter()
            .map(|h| h.get(fields::PASSWORD).unwrap_or_default().to_owned())
            .collect();
        assert!(history.contains(&"modifié sur A".to_owned()), "{history:?}");
        assert!(history.contains(&"v1".to_owned()), "{history:?}");
    }
}

#[test]
fn deletions_propagate_and_are_not_resurrected() {
    let (mut a, mut b, id) = two_copies();
    sleep(Duration::from_millis(1_100));
    a.delete_entry(&id).unwrap();
    assert!(a.entries().is_empty());
    b.merge_from(&a).unwrap();
    assert!(b.entries().is_empty());
    // L'autre sens ne fait pas réapparaître l'entrée.
    a.merge_from(&b).unwrap();
    assert!(a.entries().is_empty());
}

#[test]
fn unrelated_vaults_are_never_merged() {
    let mut a = Vault::create("A", fast_kdf()).unwrap();
    let mut b = Vault::create("B", fast_kdf()).unwrap();
    b.add_entry(&entry("Banque", "x")).unwrap();
    assert!(matches!(a.merge_from(&b), Err(Error::DifferentVaults)));
    assert!(a.entries().is_empty());
}

#[test]
fn merging_identical_copies_changes_nothing() {
    let (mut a, b, _) = two_copies();
    let report = a.merge_from(&b).unwrap();
    assert!(report.is_empty(), "{report:?}");
}

#[test]
fn rapid_edits_through_the_core_remain_ordered_and_mergeable() {
    // Le format est à la seconde. Le noyau date chaque version de façon
    // strictement croissante : les versions d'un même terminal restent
    // ordonnées, même modifiées plusieurs fois dans la seconde.
    let (mut a, b, id) = two_copies();
    for i in 0..5 {
        a.update_entry(&id, &entry("Banque", &format!("rapide {i}")))
            .unwrap();
    }
    let mut on_b = b.clone();
    let report = on_b.merge_from(&a).unwrap();
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    assert_eq!(on_b.entry(&id).unwrap().password.as_str(), "rapide 4");
    let mut on_a = a.clone();
    on_a.merge_from(&on_b).unwrap();
    assert_eq!(on_a.entry(&id).unwrap().password.as_str(), "rapide 4");
}

#[test]
fn simultaneous_edits_on_two_devices_lose_nothing() {
    // Deux terminaux modifient la même entrée presque en même temps. Si les
    // dates diffèrent, la plus récente l'emporte ; si elles tombent dans la même
    // seconde, la bibliothèque garde la version de destination et range l'autre
    // dans l'historique, avec un avertissement. Dans tous les cas, rien n'est
    // perdu.
    let (mut a, mut b, id) = two_copies();
    sleep(Duration::from_millis(1_100));
    a.update_entry(&id, &entry("Banque", "valeur A")).unwrap();
    b.update_entry(&id, &entry("Banque", "valeur B")).unwrap();
    for (mut merged, other) in [(a.clone(), &b), (b.clone(), &a)] {
        merged.merge_from(other).unwrap();
        let current = merged.entry(&id).unwrap().password.as_str().to_owned();
        let mut seen: Vec<String> = merged
            .database()
            .entry(keepass::db::EntryId::from_uuid(id.parse().unwrap()))
            .unwrap()
            .history
            .as_ref()
            .map(|h| {
                h.get_entries()
                    .iter()
                    .map(|v| v.get(fields::PASSWORD).unwrap_or_default().to_owned())
                    .collect()
            })
            .unwrap_or_default();
        seen.push(current);
        assert!(seen.contains(&"valeur A".to_owned()), "{seen:?}");
        assert!(seen.contains(&"valeur B".to_owned()), "{seen:?}");
    }
}
