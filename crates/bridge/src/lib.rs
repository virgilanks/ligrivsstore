//! Relais de messagerie native `ligrivsstore-pont` (note de conception n° 3,
//! section 6.1).
//!
//! Chrome ou Edge lance le relais à chaque liaison ouverte par l'extension,
//! avec l'origine de l'extension en premier argument. Le relais :
//!
//! 1. vérifie cette origine : seules les extensions listées dans
//!    [`ligrivsstore_protocol::EXTENSION_IDS`] passent ;
//! 2. rejoint l'application par le canal nommé du compte, et la démarre,
//!    verrouillée et cachée dans la zone de notification, si elle ne tourne
//!    pas ;
//! 3. annonce l'origine à l'application, puis transmet les trames dans les
//!    deux sens, sans les lire : elles sont chiffrées de bout en bout.
//!
//! Il ne conserve rien et n'écrit sur sa sortie standard que les trames
//! destinées au navigateur.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use ligrivsstore_protocol::{
    Envelope, ProtocolError, VERSION, extension_origin_allowed, read_frame, write_frame,
};
use ligrivsstore_win::canal::{self, ChannelName, Stream};

/// Variable d'environnement qui désigne l'application à lancer (essais).
pub const APPLICATION_VARIABLE: &str = "LIGRIVSSTORE_APPLICATION";

/// Argument qui démarre l'application cachée, dans la zone de notification.
pub const BACKGROUND_ARGUMENT: &str = "--arriere-plan";

/// Délai pour que l'application lancée ouvre son canal.
pub const LAUNCH_WAIT: Duration = Duration::from_secs(15);

/// Erreurs du relais.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    /// Appelé par autre chose qu'une extension admise.
    #[error("origine refusée : {0}")]
    Origin(String),
    /// Application introuvable ou qui ne répond pas.
    #[error("application indisponible : {0}")]
    Application(String),
    /// Échange interrompu ou trame invalide.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

impl BridgeError {
    /// Code transmis à l'extension.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Origin(_) => "origine_refusee",
            Self::Application(_) => "application_absente",
            Self::Protocol(_) => "liaison_interrompue",
        }
    }
}

/// Lit l'origine de l'extension dans les arguments du relais (le premier ;
/// Chrome et Edge ajoutent sous Windows `--parent-window=…`).
pub fn origin_from_args(mut args: impl Iterator<Item = String>) -> Result<String, BridgeError> {
    let origin = args
        .next()
        .ok_or_else(|| BridgeError::Origin("aucun argument".into()))?;
    if extension_origin_allowed(&origin) {
        Ok(origin)
    } else {
        Err(BridgeError::Origin(origin))
    }
}

/// Emplacement de l'application : `LIGRIVSSTORE_APPLICATION`, sinon
/// l'exécutable installé à côté du relais.
pub fn application_path() -> Option<PathBuf> {
    if let Some(custom) = std::env::var_os(APPLICATION_VARIABLE).filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(custom));
    }
    let name = if cfg!(windows) {
        "ligrivsstore.exe"
    } else {
        "ligrivsstore"
    };
    let candidate = std::env::current_exe().ok()?.with_file_name(name);
    candidate.is_file().then_some(candidate)
}

/// Rejoint l'application ; si elle ne tourne pas, la lance et l'attend.
pub fn connect_or_launch(
    name: &ChannelName,
    application: Option<&Path>,
    wait: Duration,
) -> Result<Stream, BridgeError> {
    if let Ok(stream) = canal::connect(name) {
        return Ok(stream);
    }
    let application = application.ok_or_else(|| {
        BridgeError::Application("application introuvable à côté du relais".into())
    })?;
    ligrivsstore_win::spawn_detached(application, &[BACKGROUND_ARGUMENT])
        .map_err(|e| BridgeError::Application(e.to_string()))?;
    let deadline = Instant::now() + wait;
    loop {
        thread::sleep(Duration::from_millis(200));
        match canal::connect(name) {
            Ok(stream) => return Ok(stream),
            Err(error) if Instant::now() >= deadline => {
                return Err(BridgeError::Application(error.to_string()));
            }
            Err(_) => {}
        }
    }
}

/// Signale une erreur au navigateur, sous forme de trame, avant de quitter.
pub fn report<W: Write>(browser_out: &mut W, error: &BridgeError) {
    let envelope = Envelope::error(error.code(), &error.to_string());
    if let Ok(bytes) = envelope.encode() {
        let _ = write_frame(browser_out, &bytes);
    }
}

/// Annonce l'origine à l'application, puis transmet les trames dans les deux
/// sens jusqu'à ce que l'un des deux côtés ferme la liaison.
pub fn relay<I, O, S>(
    browser_in: I,
    browser_out: O,
    app: Arc<S>,
    origin: &str,
) -> Result<(), BridgeError>
where
    I: Read + Send + 'static,
    O: Write + Send + 'static,
    S: Send + Sync + 'static,
    for<'a> &'a S: Read + Write,
{
    let announce = Envelope::Bridge {
        v: VERSION,
        origin: origin.to_owned(),
    }
    .encode()?;
    let mut writer: &S = &app;
    write_frame(&mut writer, &announce)?;

    let (done, finished) = mpsc::channel();
    let to_app = Arc::clone(&app);
    let browser_done = done.clone();
    thread::Builder::new()
        .name("navigateur-vers-application".into())
        .spawn(move || {
            let mut writer: &S = &to_app;
            let _ = browser_done.send(pump(browser_in, &mut writer));
        })
        .map_err(ProtocolError::Io)?;
    let from_app = Arc::clone(&app);
    thread::Builder::new()
        .name("application-vers-navigateur".into())
        .spawn(move || {
            let reader: &S = &from_app;
            let _ = done.send(pump(reader, browser_out));
        })
        .map_err(ProtocolError::Io)?;
    // La première fin, d'un côté ou de l'autre, termine le relais.
    match finished.recv() {
        Ok(result) => result.map_err(BridgeError::from),
        Err(_) => Ok(()),
    }
}

fn pump<R: Read, W: Write>(mut from: R, mut to: W) -> Result<(), ProtocolError> {
    while let Some(frame) = read_frame(&mut from)? {
        write_frame(&mut to, &frame)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Mutex;

    use super::*;

    const ORIGIN: &str = "chrome-extension://pbjfabapbnileccikicpifdnhkocnlbb/";

    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn frames(payloads: &[&[u8]]) -> Vec<u8> {
        let mut buffer = Vec::new();
        for payload in payloads {
            write_frame(&mut buffer, payload).unwrap();
        }
        buffer
    }

    fn read_all(bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut reader = bytes;
        let mut out = Vec::new();
        while let Some(frame) = read_frame(&mut reader).unwrap() {
            out.push(frame);
        }
        out
    }

    fn unique_channel() -> ChannelName {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let id = format!("ligrivsstore-pont-essai-{}-{stamp}", std::process::id());
        if cfg!(windows) {
            ChannelName::custom(id)
        } else {
            ChannelName::custom(
                std::env::temp_dir()
                    .join(id)
                    .join("canal.sock")
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    }

    #[test]
    fn only_an_allowed_extension_may_start_the_relay() {
        let args = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            origin_from_args(args(&[ORIGIN, "--parent-window=1234"]).into_iter()).unwrap(),
            ORIGIN
        );
        for bad in [
            &[][..],
            &["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"][..],
            &["--parent-window=1234", ORIGIN][..],
            &["C:\\chemin\\manifeste.json", "{id@exemple}"][..],
        ] {
            let error = origin_from_args(args(bad).into_iter()).unwrap_err();
            assert_eq!(error.code(), "origine_refusee");
        }
    }

    #[test]
    fn frames_cross_the_relay_unchanged_after_the_origin() {
        let name = unique_channel();
        let listener = canal::listen(&name).unwrap();
        // L'application : lit l'annonce et deux trames, répond deux fois.
        let app = thread::spawn(move || {
            let stream = listener.accept().unwrap();
            let mut reader: &Stream = &stream;
            let announce = read_frame(&mut reader).unwrap().unwrap();
            let first = read_frame(&mut reader).unwrap().unwrap();
            let second = read_frame(&mut reader).unwrap().unwrap();
            let mut writer: &Stream = &stream;
            write_frame(&mut writer, b"{\"reponse\":1}").unwrap();
            write_frame(&mut writer, b"{\"reponse\":2}").unwrap();
            // L'application ferme sa liaison en partant : le relais s'arrête.
            (announce, first, second)
        });
        let stream = Arc::new(canal::connect(&name).unwrap());
        let browser_in = Cursor::new(frames(&[b"{\"requete\":1}", b"{\"requete\":2}"]));
        let browser_out = Shared::default();
        // Le navigateur ferme sa sortie après deux trames : fin du relais.
        relay(browser_in, browser_out.clone(), Arc::clone(&stream), ORIGIN).unwrap();
        drop(stream);
        let (announce, first, second) = app.join().unwrap();
        assert_eq!(
            Envelope::decode(&announce).unwrap(),
            Envelope::Bridge {
                v: VERSION,
                origin: ORIGIN.into()
            }
        );
        assert_eq!(first, b"{\"requete\":1}");
        assert_eq!(second, b"{\"requete\":2}");
        // Les réponses arrivent au navigateur, au plus tard à la fermeture.
        let deadline = Instant::now() + Duration::from_secs(5);
        while read_all(&browser_out.0.lock().unwrap()).len() < 2 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            read_all(&browser_out.0.lock().unwrap()),
            [b"{\"reponse\":1}".to_vec(), b"{\"reponse\":2}".to_vec()]
        );
    }

    #[test]
    fn an_oversized_frame_from_the_browser_ends_the_relay() {
        let name = unique_channel();
        let listener = canal::listen(&name).unwrap();
        let app = thread::spawn(move || {
            let stream = listener.accept().unwrap();
            let mut reader: &Stream = &stream;
            // L'annonce passe ; la trame trop grande est refusée par le relais
            // avant toute transmission.
            let announce = read_frame(&mut reader).unwrap().unwrap();
            (stream, announce)
        });
        let stream = Arc::new(canal::connect(&name).unwrap());
        let mut oversized = ((ligrivsstore_protocol::MAX_FRAME + 1) as u32)
            .to_le_bytes()
            .to_vec();
        oversized.extend_from_slice(b"...");
        let result = relay(
            Cursor::new(oversized),
            Shared::default(),
            Arc::clone(&stream),
            ORIGIN,
        );
        assert!(matches!(
            result,
            Err(BridgeError::Protocol(ProtocolError::TooLarge(_)))
        ));
        let (_app_side, announce) = app.join().unwrap();
        assert!(matches!(
            Envelope::decode(&announce).unwrap(),
            Envelope::Bridge { .. }
        ));
        drop(stream);
    }

    #[test]
    fn without_the_app_the_relay_launches_it_or_reports_its_absence() {
        let name = unique_channel();
        let error = connect_or_launch(&name, None, Duration::from_millis(10)).unwrap_err();
        assert_eq!(error.code(), "application_absente");
        let missing = Path::new("/chemin/inexistant/ligrivsstore");
        let error = connect_or_launch(&name, Some(missing), Duration::from_millis(10)).unwrap_err();
        assert_eq!(error.code(), "application_absente");
        // L'erreur part vers le navigateur sous forme de trame.
        let mut out = Vec::new();
        report(&mut out, &error);
        let envelope = Envelope::decode(&read_all(&out)[0]).unwrap();
        assert!(matches!(envelope, Envelope::Error { code, .. } if code == "application_absente"));
    }
}
