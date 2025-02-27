# OtimizacaoWindows
# Desabilitar ferramentas desnecessarias e Limpeza.

# Verifica se o script estÃ¡ sendo executado como administrador
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Este script requer privilÃ©gios de administrador. Solicitando elevaÃ§Ã£o..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Exit
}

Write-Host "Iniciando otimizaÃ§Ãµes avanÃ§adas extremas para seu Windows (com Wi-Fi e Spooler preservados)..." -ForegroundColor Green

# 1. Desativar efeitos visuais completamente e ajustes adicionais de interface
Write-Host "Desativando todos os efeitos visuais e otimizando interface..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00))
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothing" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "Composition" -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "BorderWidth" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Value 0

# 2. Desativar serviÃ§os desnecessÃ¡rios (exceto Wi-Fi e Spooler)
Write-Host "Desativando serviÃ§os desnecessÃ¡rios (mantendo Wi-Fi e Spooler)..."
$services = @(
    "XblAuthManager", "XblGameSave", "XboxNetApiSvc", "XboxGipSvc", # ServiÃ§os Xbox
    "DiagTrack", "dmwappushservice", "DPS", "WdiServiceHost",       # Telemetria e diagnÃ³sticos
    "MapsBroker", "WMPNetworkSvc", "WwanSvc",                      # Mapas, Media Player, WWAN
    "SysMain", "WSearch", "defragsvc",                             # Superfetch, busca e desfragmentaÃ§Ã£o
    "Fax", "PrintNotify",                                          # Fax e notificaÃ§Ãµes de impressÃ£o (Spooler preservado)
    "wuauserv", "DoSvc", "UsoSvc", "WaaSMedicSvc",                 # Windows Update e serviÃ§os relacionados
    "PcaSvc", "RetailDemo", "AppXSvc",                            # Compatibilidade, demo e apps UWP
    "TabletInputService", "TouchKeyboard",                         # Suporte a tablets e teclado virtual
    "BcastDVRUserService_*", "GameDVR",                            # GravaÃ§Ã£o de jogos
    "WerSvc", "TroubleShootingSvc",                                # RelatÃ³rios de erro
    "lfsvc", "icssvc", "WalletService"                             # Geolocation, SMS, Wallet
)
foreach ($service in $services) {
    if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
        Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host "ServiÃ§o $service desativado."
    }
}

# 3. Desativar inicializaÃ§Ã£o rÃ¡pida, hibernaÃ§Ã£o, swap e ajustes de memÃ³ria
Write-Host "Otimizando inicializaÃ§Ã£o e gerenciamento de memÃ³ria..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0
powercfg /hibernate off
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value ""
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1

# 4. Configurar plano de energia para desempenho extremo
Write-Host "Configurando plano de energia para desempenho extremo..."
powercfg /duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg /change standby-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 100
powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100
powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR IDLE 0

# 5. Limpeza extrema de arquivos temporÃ¡rios e caches
Write-Host "Executando limpeza extrema de arquivos temporÃ¡rios..."
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" -Recurse -Force -ErrorAction SilentlyContinue
Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -NoNewWindow -Wait

# 6. Desativar todas as tarefas agendadas desnecessÃ¡rias
Write-Host "Desativando todas as tarefas agendadas desnecessÃ¡rias..."
$tasks = @(
    "\Microsoft\Windows\Application Experience\*",
    "\Microsoft\Windows\Customer Experience Improvement Program\*",
    "\Microsoft\Windows\Defrag\*",
    "\Microsoft\Windows\Maintenance\*",
    "\Microsoft\Windows\Power Efficiency Diagnostics\*",
    "\Microsoft\Windows\WindowsUpdate\*",
    "\Microsoft\Windows\DiskCleanup\*",
    "\Microsoft\Windows\CloudExperienceHost\*",
    "\Microsoft\Windows\Feedback\*",
    "\Microsoft\Windows\Maps\*"
)
foreach ($task in $tasks) {
    schtasks /change /tn $task /disable -ErrorAction SilentlyContinue
    Write-Host "Tarefa $task desativada."
}

# 7. Desativar mais recursos do Windows (mantendo suporte a impressÃ£o)
Write-Host "Desativando recursos desnecessÃ¡rios do Windows..."
$features = @(
    "WindowsMediaFeatures", "Internet-Explorer-Optional-amd64",
    "Microsoft-Windows-Subsystem-Linux", "WorkFolders-Client",
    "Microsoft-Hyper-V-All", "Windows-Defender-Default-Definitions",
    "SMB1Protocol"
)
foreach ($feature in $features) {
    Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction SilentlyContinue
    Write-Host "Recurso $feature desativado."
}

# 8. Otimizar processador e rede (mantendo Wi-Fi funcional)
Write-Host "Otimizando processador e rede..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" -Name "Value" -Value 100
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "DisableBandwidthThrottling" -Value 1

# 9. Desativar mais notificaÃ§Ãµes e telemetria
Write-Host "Eliminando notificaÃ§Ãµes e telemetria..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -ErrorAction SilentlyContinue

# 10. VerificaÃ§Ã£o e reparo
Write-Host "Verificando e reparando integridade do sistema..."
sfc /scannow
DISM /Online /Cleanup-Image /RestoreHealth

Write-Host "OtimizaÃ§Ã£o extrema concluÃ­da! Reinicie o sistema para aplicar todas as mudanÃ§as." -ForegroundColor Green
