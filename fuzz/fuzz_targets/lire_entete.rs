//! Cible : lecture de l'en-tête par le noyau. Aucune entrée ne doit provoquer
//! d'arrêt brutal.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ligrivsstore_core::{OpenLimits, header};

fuzz_target!(|data: &[u8]| {
    if let Ok(info) = header::inspect(data) {
        let _ = OpenLimits::default().check(&info);
        let _ = info.kdf.to_string();
    }
});
