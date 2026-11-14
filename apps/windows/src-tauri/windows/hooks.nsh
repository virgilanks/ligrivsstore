; Étapes ajoutées à l'installateur NSIS produit par Tauri (décision 0012).
;
; À l'installation : déclaration du relais de messagerie native auprès de
; Chrome et d'Edge, pour l'utilisateur courant (sans droits d'administrateur).
; Le manifeste com.ligrivs.ligrivsstore.json est installé à côté de
; l'application et du relais ligrivsstore-pont.exe. L'application vérifie aussi
; ces déclarations à chaque démarrage.
;
; À la désinstallation : retrait de ces déclarations et du démarrage avec
; Windows. Le coffre, ses sauvegardes et le fichier clé restent en place.

!macro NSIS_HOOK_POSTINSTALL
  WriteRegStr HKCU "Software\Google\Chrome\NativeMessagingHosts\com.ligrivs.ligrivsstore" "" "$INSTDIR\com.ligrivs.ligrivsstore.json"
  WriteRegStr HKCU "Software\Microsoft\Edge\NativeMessagingHosts\com.ligrivs.ligrivsstore" "" "$INSTDIR\com.ligrivs.ligrivsstore.json"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DeleteRegKey HKCU "Software\Google\Chrome\NativeMessagingHosts\com.ligrivs.ligrivsstore"
  DeleteRegKey HKCU "Software\Microsoft\Edge\NativeMessagingHosts\com.ligrivs.ligrivsstore"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "ligrivsstore"
!macroend
