//! Appels directs à Windows : surveillance du verrouillage de la session et
//! de la mise en veille ; identifiant de sécurité (SID) du compte, pour le
//! canal nommé ; protection des clés par DPAPI.
//!
//! Une fenêtre cachée, créée sur un fil dédié, reçoit de Windows :
//!
//! - `WM_WTSSESSION_CHANGE`, après inscription par
//!   `WTSRegisterSessionNotification` : verrouillage, fermeture ou
//!   déconnexion de la session ;
//! - `WM_POWERBROADCAST` (`PBT_APMSUSPEND`), diffusé à toutes les fenêtres de
//!   premier niveau avant une mise en veille.
//!
//! C'est le seul module du dépôt où du code `unsafe` est admis : chaque bloc
//! ne contient qu'un appel à Windows, justifié par un commentaire SAFETY.
#![allow(unsafe_code)]

use std::ptr;
use std::sync::OnceLock;
use std::sync::mpsc;
use std::thread;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, HANDLE_FLAG_INHERIT, HLOCAL, HWND, INVALID_HANDLE_VALUE,
    LPARAM, LRESULT, LocalFree, SetHandleInformation, WPARAM,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::RemoteDesktop::{
    NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, MSG, PBT_APMSUSPEND,
    RegisterClassExW, TranslateMessage, WM_POWERBROADCAST, WM_WTSSESSION_CHANGE, WNDCLASSEXW,
    WS_OVERLAPPED, WTS_CONSOLE_DISCONNECT, WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK,
    WTS_SESSION_LOGOFF,
};
use zeroize::Zeroizing;

use crate::{SystemEvent, WinError};

type Handler = Box<dyn Fn(SystemEvent) + Send + Sync>;

/// Destinataire des événements, fixé une fois pour toutes : la procédure de
/// fenêtre, appelée par Windows, n'a pas d'autre moyen sûr de le joindre.
static HANDLER: OnceLock<Handler> = OnceLock::new();

const CLASS_NAME: &str = "ligrivsstore.systeme";

/// Démarre la surveillance ; renvoie le descripteur de la fenêtre cachée
/// (sous forme d'entier, pour les essais).
pub(crate) fn watch(handler: Handler) -> Result<usize, WinError> {
    HANDLER
        .set(handler)
        .map_err(|_| WinError::AlreadyWatching)?;
    let (ready, started) = mpsc::channel();
    thread::Builder::new()
        .name("ligrivsstore-systeme".into())
        .spawn(move || match create_window() {
            Ok(window) => {
                let _ = ready.send(Ok(window as usize));
                run_message_loop();
            }
            Err(error) => {
                let _ = ready.send(Err(error));
            }
        })
        .map_err(|e| WinError::Thread(e.to_string()))?;
    started
        .recv()
        .map_err(|e| WinError::Thread(e.to_string()))?
}

fn create_window() -> Result<HWND, WinError> {
    let class_name: Vec<u16> = CLASS_NAME.encode_utf16().chain(Some(0)).collect();
    // SAFETY: un nom de module nul désigne l'exécutable du processus courant ;
    // le descripteur renvoyé n'a pas à être libéré.
    let instance = unsafe { GetModuleHandleW(ptr::null()) };
    if instance.is_null() {
        return Err(last_error("GetModuleHandleW"));
    }
    let class = WNDCLASSEXW {
        cbSize: size_of::<WNDCLASSEXW>() as u32,
        lpfnWndProc: Some(window_procedure),
        hInstance: instance,
        lpszClassName: class_name.as_ptr(),
        ..Default::default()
    };
    // SAFETY: `class` est entièrement initialisée (champs non cités à zéro,
    // valeur admise par Windows) ; Windows copie le nom de classe, et
    // `class_name` reste valide pendant l'appel.
    let atom = unsafe { RegisterClassExW(&class) };
    if atom == 0 {
        return Err(last_error("RegisterClassExW"));
    }
    // SAFETY: la classe vient d'être enregistrée pour ce module ; les noms sont
    // des chaînes UTF-16 terminées par zéro, valides pendant l'appel. Fenêtre
    // de premier niveau (pour recevoir WM_POWERBROADCAST), jamais affichée,
    // sans parent, sans menu et sans paramètre de création.
    let window = unsafe {
        CreateWindowExW(
            0,
            class_name.as_ptr(),
            class_name.as_ptr(),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            instance,
            ptr::null(),
        )
    };
    if window.is_null() {
        return Err(last_error("CreateWindowExW"));
    }
    // SAFETY: `window` est une fenêtre valide, créée par ce fil, qui vivra
    // jusqu'à la fin du processus.
    let registered = unsafe { WTSRegisterSessionNotification(window, NOTIFY_FOR_THIS_SESSION) };
    if registered == 0 {
        return Err(last_error("WTSRegisterSessionNotification"));
    }
    Ok(window)
}

fn run_message_loop() {
    let mut message = MSG::default();
    loop {
        // SAFETY: `message` est un tampon valide, réservé à ce fil ; un
        // descripteur de fenêtre nul demande tous les messages de ce fil.
        let status = unsafe { GetMessageW(&mut message, ptr::null_mut(), 0, 0) };
        if status == 0 || status == -1 {
            break;
        }
        // SAFETY: `message` vient d'être rempli par GetMessageW.
        unsafe { TranslateMessage(&message) };
        // SAFETY: idem ; la procédure appelée est `window_procedure`.
        unsafe { DispatchMessageW(&message) };
    }
}

/// Procédure de la fenêtre cachée. Elle ne fait que transmettre les
/// événements utiles : le destinataire ne doit pas bloquer ce fil.
unsafe extern "system" fn window_procedure(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_WTSSESSION_CHANGE => {
            let change = u32::try_from(wparam).unwrap_or(0);
            if matches!(
                change,
                WTS_SESSION_LOCK
                    | WTS_SESSION_LOGOFF
                    | WTS_CONSOLE_DISCONNECT
                    | WTS_REMOTE_DISCONNECT
            ) {
                notify(SystemEvent::SessionLocked);
            }
            0
        }
        WM_POWERBROADCAST => {
            if u32::try_from(wparam).ok() == Some(PBT_APMSUSPEND) {
                notify(SystemEvent::Suspending);
            }
            // TRUE : la mise en veille n'est jamais retardée.
            1
        }
        _ => {
            // SAFETY: paramètres reçus de Windows pour cette fenêtre, transmis
            // sans modification au traitement par défaut.
            unsafe { DefWindowProcW(window, message, wparam, lparam) }
        }
    }
}

fn notify(event: SystemEvent) {
    if let Some(handler) = HANDLER.get() {
        handler(event);
    }
}

// ---------------------------------------------------------------------------
// Compte Windows : identifiant de sécurité (SID) de l'utilisateur.

/// Descripteur de jeton, fermé à la fin de sa portée.
struct TokenHandle(HANDLE);

impl Drop for TokenHandle {
    fn drop(&mut self) {
        // SAFETY: descripteur ouvert par OpenProcessToken, fermé une seule
        // fois, ici.
        unsafe { CloseHandle(self.0) };
    }
}

/// Mémoire allouée par Windows (LocalAlloc), libérée à la fin de sa portée.
struct LocalMemory(HLOCAL);

impl Drop for LocalMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: mémoire allouée par Windows pour nous, libérée une seule
            // fois, ici.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// SID du compte qui exécute le processus, en texte (`S-1-5-21-…`).
pub(crate) fn current_user_sid() -> Result<String, WinError> {
    // SAFETY: pseudo-descripteur du processus courant, toujours valide, qui
    // n'a pas à être fermé.
    let process = unsafe { GetCurrentProcess() };
    let mut raw_token: HANDLE = ptr::null_mut();
    // SAFETY: `raw_token` est une variable locale où Windows écrit le
    // descripteur du jeton, ouvert en lecture seule.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(last_error("OpenProcessToken"));
    }
    let token = TokenHandle(raw_token);
    let mut needed = 0u32;
    // SAFETY: appel de mesure, sans tampon : Windows n'écrit que la taille
    // requise dans `needed` (l'échec ERROR_INSUFFICIENT_BUFFER est attendu).
    unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err(last_error("GetTokenInformation"));
    }
    // Tampon aligné sur 8 octets, comme l'exige TOKEN_USER.
    let words = (needed as usize).div_ceil(8);
    let mut buffer = vec![0u64; words];
    let capacity = u32::try_from(words * 8).map_err(|_| WinError::Api {
        function: "GetTokenInformation",
        code: 0,
    })?;
    // SAFETY: le tampon, aligné sur 8 octets, fait `capacity` octets, au
    // moins `needed` ; Windows y écrit une structure TOKEN_USER suivie du SID.
    let filled = unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            capacity,
            &mut needed,
        )
    };
    if filled == 0 {
        return Err(last_error("GetTokenInformation"));
    }
    // SAFETY: Windows vient d'écrire une structure TOKEN_USER valide en tête
    // du tampon, aligné ; la référence ne survit pas au tampon.
    let user: &TOKEN_USER = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut text: *mut u16 = ptr::null_mut();
    // SAFETY: le SID pointe dans le tampon, vivant pendant l'appel ; Windows
    // alloue la chaîne, libérée par LocalFree (garde ci-dessous).
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
        return Err(last_error("ConvertSidToStringSidW"));
    }
    let memory = LocalMemory(text.cast());
    let sid = wide_to_string(text);
    drop(memory);
    Ok(sid)
}

/// Lit une chaîne UTF-16 terminée par zéro, allouée par Windows.
fn wide_to_string(text: *const u16) -> String {
    let mut length = 0usize;
    loop {
        // SAFETY: la chaîne se termine par un zéro : on avance jusqu'à lui,
        // sans le dépasser.
        let position = unsafe { text.add(length) };
        // SAFETY: `position` est dans la chaîne, zéro final compris.
        let unit = unsafe { *position };
        if unit == 0 {
            break;
        }
        length += 1;
    }
    // SAFETY: `length` unités UTF-16 valides et initialisées précèdent le zéro.
    let units = unsafe { std::slice::from_raw_parts(text, length) };
    String::from_utf16_lossy(units)
}

// ---------------------------------------------------------------------------
// DPAPI : protection de données liée au compte Windows.

/// Bloc alloué par DPAPI, effacé (s'il contient un secret) puis libéré.
struct DpapiBlob {
    blob: CRYPT_INTEGER_BLOB,
    secret: bool,
}

impl DpapiBlob {
    fn bytes(&self) -> &[u8] {
        if self.blob.pbData.is_null() || self.blob.cbData == 0 {
            return &[];
        }
        // SAFETY: DPAPI a alloué `cbData` octets initialisés à `pbData`,
        // valides jusqu'à la libération dans `drop`.
        unsafe { std::slice::from_raw_parts(self.blob.pbData, self.blob.cbData as usize) }
    }
}

impl Drop for DpapiBlob {
    fn drop(&mut self) {
        if self.blob.pbData.is_null() {
            return;
        }
        if self.secret {
            // SAFETY: mêmes octets que dans `bytes`, que personne d'autre ne
            // détient ; effacés avant la libération.
            let bytes = unsafe {
                std::slice::from_raw_parts_mut(self.blob.pbData, self.blob.cbData as usize)
            };
            zeroize::Zeroize::zeroize(bytes);
        }
        // SAFETY: mémoire allouée par DPAPI pour nous, libérée une seule fois.
        unsafe { LocalFree(self.blob.pbData.cast()) };
    }
}

fn input_blob(data: &[u8]) -> Result<CRYPT_INTEGER_BLOB, WinError> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).map_err(|_| WinError::Api {
            function: "CryptProtectData",
            code: 0,
        })?,
        // DPAPI ne modifie pas les données d'entrée.
        pbData: data.as_ptr().cast_mut(),
    })
}

/// Chiffre `data` pour le seul compte Windows courant.
pub(crate) fn protect(data: &[u8], description: &str) -> Result<Vec<u8>, WinError> {
    let input = input_blob(data)?;
    let description: Vec<u16> = description.encode_utf16().chain(Some(0)).collect();
    let mut output = DpapiBlob {
        blob: CRYPT_INTEGER_BLOB::default(),
        secret: false,
    };
    // SAFETY: entrée et description valides pendant l'appel ; aucune
    // interface (CRYPTPROTECT_UI_FORBIDDEN) ; DPAPI alloue la sortie, libérée
    // par la garde `output`.
    let done = unsafe {
        CryptProtectData(
            &input,
            description.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output.blob,
        )
    };
    if done == 0 {
        return Err(last_error("CryptProtectData"));
    }
    Ok(output.bytes().to_vec())
}

/// Déchiffre un bloc produit par [`protect`] sous le même compte.
pub(crate) fn unprotect(blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, WinError> {
    let input = input_blob(blob)?;
    let mut output = DpapiBlob {
        blob: CRYPT_INTEGER_BLOB::default(),
        secret: true,
    };
    // SAFETY: entrée valide pendant l'appel ; ni description demandée, ni
    // entropie, ni interface ; DPAPI alloue la sortie, effacée puis libérée
    // par la garde `output`.
    let done = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output.blob,
        )
    };
    if done == 0 {
        return Err(last_error("CryptUnprotectData"));
    }
    Ok(Zeroizing::new(output.bytes().to_vec()))
}

// ---------------------------------------------------------------------------
// Entrées et sorties standard non héritées par les programmes lancés.

/// Les entrées et sorties standard du processus (les tubes ouverts par le
/// navigateur pour le relais) ne seront pas héritées par les programmes qu'il
/// lance : sinon, l'application lancée par le relais garderait ces tubes
/// ouverts, et le navigateur ne verrait jamais la fin du relais.
pub(crate) fn stop_std_handle_inheritance() {
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: lecture d'un descripteur standard du processus, sans effet
        // de bord ; il n'a pas à être fermé.
        let handle = unsafe { GetStdHandle(which) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            continue;
        }
        // SAFETY: descripteur valide du processus ; seul l'indicateur
        // d'héritage est retiré.
        unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
    }
}

fn last_error(function: &'static str) -> WinError {
    // SAFETY: lecture du dernier code d'erreur du fil courant, sans effet de
    // bord.
    let code = unsafe { GetLastError() };
    WinError::Api { function, code }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use windows_sys::Win32::UI::WindowsAndMessaging::{
        PBT_APMRESUMEAUTOMATIC, PostMessageW, WTS_SESSION_UNLOCK,
    };

    use super::*;

    fn post(window: usize, message: u32, wparam: u32) {
        // SAFETY: `window` est la fenêtre cachée créée par `watch`, vivante
        // jusqu'à la fin du processus ; PostMessageW ne fait que déposer le
        // message dans sa file.
        let posted = unsafe { PostMessageW(window as HWND, message, wparam as WPARAM, 0) };
        assert_ne!(posted, 0, "PostMessageW");
    }

    #[test]
    fn the_account_sid_is_read() {
        let sid = current_user_sid().unwrap();
        assert!(sid.starts_with("S-1-5-"), "{sid}");
        assert!(sid.len() > 10);
        assert_eq!(current_user_sid().unwrap(), sid);
    }

    #[test]
    fn dpapi_round_trip_and_tampering() {
        let secret = b"cle d'appairage de l'application";
        let blob = protect(secret, "ligrivsstore").unwrap();
        assert!(!blob.windows(secret.len()).any(|w| w == secret), "chiffré");
        assert_eq!(unprotect(&blob).unwrap().as_slice(), secret);
        let mut altered = blob.clone();
        let last = altered.len() - 1;
        altered[last] ^= 0x55;
        assert!(unprotect(&altered).is_err());
        assert!(unprotect(b"pas un bloc DPAPI").is_err());
    }

    // La surveillance est unique dans un processus : un seul essai.
    #[test]
    fn session_and_power_messages_reach_the_handler_once_and_only_when_relevant() {
        let (sender, events) = mpsc::channel();
        let window = watch(Box::new(move |event| {
            let _ = sender.send(event);
        }))
        .unwrap();
        assert!(matches!(
            watch(Box::new(|_| {})),
            Err(WinError::AlreadyWatching)
        ));

        let wait = Duration::from_secs(5);
        post(window, WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK);
        assert_eq!(events.recv_timeout(wait), Ok(SystemEvent::SessionLocked));
        post(window, WM_POWERBROADCAST, PBT_APMSUSPEND);
        assert_eq!(events.recv_timeout(wait), Ok(SystemEvent::Suspending));
        post(window, WM_WTSSESSION_CHANGE, WTS_CONSOLE_DISCONNECT);
        assert_eq!(events.recv_timeout(wait), Ok(SystemEvent::SessionLocked));

        // Déverrouillage et reprise ne verrouillent rien.
        post(window, WM_WTSSESSION_CHANGE, WTS_SESSION_UNLOCK);
        post(window, WM_POWERBROADCAST, PBT_APMRESUMEAUTOMATIC);
        assert!(events.recv_timeout(Duration::from_millis(500)).is_err());
    }
}
