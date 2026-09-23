; ⛔ Перед установкой обязательно снять наши же процессы-спутники.
;
; Сторож (--restore-guard) и обёртка TUN режима (--run-tunnel) — это тот
; же nexusproxy.exe, запущенный с особым доводом. Они живут отдельно от
; окна программы и держат файл: установщик не может его перезаписать и
; показывает «Error opening file for writing», а автообновление молча
; ломается.

!macro NSIS_HOOK_PREINSTALL
  DetailPrint "Останавливаю перехват трафика…"
  nsExec::Exec 'schtasks.exe /end /tn NexusProxyTunnel'
  Pop $0
  DetailPrint "Закрываю спутники программы…"
  ; сначала по-хорошему, потом принудительно
  nsExec::Exec 'taskkill /IM nexusproxy.exe /T'
  Pop $0
  Sleep 800
  nsExec::Exec 'taskkill /F /IM nexusproxy.exe /T'
  Pop $0
  nsExec::Exec 'taskkill /F /IM sing-box.exe /T'
  Pop $0
  Sleep 500
!macroend

; ⛔ При удалении — то же самое, иначе останутся работать перехват и
; сетевой интерфейс, а программы уже нет.
!macro NSIS_HOOK_PREUNINSTALL
  nsExec::Exec 'schtasks.exe /end /tn NexusProxyTunnel'
  Pop $0
  nsExec::Exec 'schtasks.exe /delete /tn NexusProxyTunnel /f'
  Pop $0
  nsExec::Exec 'taskkill /F /IM nexusproxy.exe /T'
  Pop $0
  nsExec::Exec 'taskkill /F /IM sing-box.exe /T'
  Pop $0
!macroend
