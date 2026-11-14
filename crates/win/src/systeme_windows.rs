//! Surveillance du verrouillage de la session et de la mise en veille.
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

use windows_sys::Win32::Foundation::{GetLastError, HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::RemoteDesktop::{
    NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, MSG, PBT_APMSUSPEND,
    RegisterClassExW, TranslateMessage, WM_POWERBROADCAST, WM_WTSSESSION_CHANGE, WNDCLASSEXW,
    WS_OVERLAPPED, WTS_CONSOLE_DISCONNECT, WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK,
    WTS_SESSION_LOGOFF,
};

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
