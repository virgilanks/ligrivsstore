//! `ligrivsstore-pont` : relais de messagerie native entre Chrome ou Edge et
//! l'application ligrivsstore. Voir la documentation du paquet
//! `ligrivsstore-bridge`.

use std::process::ExitCode;
use std::sync::Arc;

use ligrivsstore_bridge::{
    BridgeError, LAUNCH_WAIT, application_path, connect_or_launch, origin_from_args, relay, report,
};
use ligrivsstore_win::canal::ChannelName;

fn main() -> ExitCode {
    let mut stdout = std::io::stdout();
    let result = (|| -> Result<(), BridgeError> {
        let origin = origin_from_args(std::env::args().skip(1))?;
        let name =
            ChannelName::for_current_user().map_err(|e| BridgeError::Application(e.to_string()))?;
        let app = connect_or_launch(&name, application_path().as_deref(), LAUNCH_WAIT)?;
        relay(std::io::stdin(), std::io::stdout(), Arc::new(app), &origin)
    })();
    match result {
        Ok(()) => {
            // L'autre sens est peut-être encore bloqué en lecture : la fin du
            // processus ferme tout.
            std::process::exit(0);
        }
        Err(error) => {
            eprintln!("ligrivsstore-pont : {error}");
            report(&mut stdout, &error);
            ExitCode::FAILURE
        }
    }
}
