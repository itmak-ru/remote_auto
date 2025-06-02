# ===== БЛОК КОНФИГУРАЦИИ =====

# Чтение конфигурации
$configPath = "C:\ProgramData\Remote_Auto\config_vars.json"

if (-not (Test-Path $configPath)) {
    Write-Error "Конфигурационный файл не найден: $configPath"
    exit 1
}

try {
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
    $protocolFiles = $config.protocolFiles
}
catch {
    Write-Error "Ошибка чтения конфигурации: $_"
    exit 1
}

# Пути для скачанных файлов
$localFilesDir = "C:\ProgramData\Remote_Auto\files"
New-Item -Path $localFilesDir -ItemType Directory -Force | Out-Null

# Пути для учетных данных
$credFolder = "C:\ProgramData\Remote_Auto\creds"
$keyFile = Join-Path $credFolder "encryption_key.bin"

# Инициализация статуса ошибок
$globalError = $false

# ===== ФУНКЦИЯ ДЛЯ ПОЛУЧЕНИЯ УЧЕТНЫХ ДАННЫХ =====
function Get-ProtocolCredentials {
    param(
        [Parameter(Mandatory = $true)]
        $ProtocolConfig,
        [Parameter(Mandatory = $true)]
        [ValidateSet('smb', 'ftp')]
        [string]$Protocol
    )
    
    $passPlain = $ProtocolConfig.passwordPlain
    $user = $ProtocolConfig.user
    
    $credFile = Join-Path $credFolder "cred_${Protocol}_pwd.txt"

    try {
        $securePass = $null
        
        if (-not [string]::IsNullOrEmpty($passPlain)) {
            $securePass = ConvertTo-SecureString $passPlain -AsPlainText -Force -ErrorAction Stop
            Write-Host "Используется открытый пароль для $Protocol" -ForegroundColor Green
        }
        elseif ((Test-Path $credFile) -and (Test-Path $keyFile)) {
            try {
                $key = [System.IO.File]::ReadAllBytes($keyFile)
                $encryptedPassword = Get-Content $credFile -ErrorAction Stop
                $securePass = ConvertTo-SecureString -String $encryptedPassword -Key $key -ErrorAction Stop
                Write-Host "Пароль загружен (AES) для $Protocol" -ForegroundColor Yellow
            }
            catch {
                Write-Warning "Ошибка дешифровки пароля для $Protocol : $_"
                throw "Не удалось получить пароль: ни открытый пароль не задан, ни зашифрованный не прочитан."
            }
        }
        else {
            throw "Пароль не найден: отсутствуют файлы $($credFile) и $($keyFile)."
        }

        if ($Protocol -eq 'ftp') {
            return New-Object System.Net.NetworkCredential($user, $securePass)
        }
        else {
            return New-Object System.Management.Automation.PSCredential ($user, $securePass)
        }
    }
    catch {
        Write-Error "Ошибка при работе с паролем для $Protocol : $_"
        exit 1
    }
}



# ===== 1. ЗАГРУЗКА ФАЙЛОВ В ЗАВИСИМОСТИ ОТ ПРОТОКОЛА =====
Write-Host "`n===== ЗАГРУЗКА ФАЙЛОВ ($protocolFiles) ====="

# Обработка для протокола FTP
if ($protocolFiles -eq "ftp") {
    # Параметры FTP
    $ftpConfig = $config.ftp
    $ftpFilesPath = "ftp://$($ftpConfig.server)/$($ftpConfig.filesFullPath)/" -replace '(?<!:)/{2,}', '/'

    # Получение учетных данных для FTP
    $ftpCred = Get-ProtocolCredentials -ProtocolConfig $ftpConfig -Protocol "ftp"

    $ftpFiles = @(
        @{Remote = "_soft/7z2409-x64.exe"; Local = "7z2409-x64.exe"},
        @{Remote = "_soft/7zip_opts.reg"; Local = "7zip_opts.reg"},
        @{Remote = "_soft/AkelPad-4.9.8-x64-setup.exe"; Local = "AkelPad-4.9.8-x64-setup.exe"},
        @{Remote = "_soft/HashTab_v6.0.0.34_Setup.exe"; Local = "HashTab_v6.0.0.34_Setup.exe"},
        @{Remote = "_soft/K-Lite_Codec_Pack_1840_Mega.exe"; Local = "K-Lite_Codec_Pack_1840_Mega.exe"},
        @{Remote = "_soft/Unlocker_x64_1.9.2.msi"; Local = "Unlocker_x64_1.9.2.msi"}
    )

    $webClient = New-Object System.Net.WebClient
    $webClient.Credentials = $ftpCred

    foreach ($file in $ftpFiles) {
        $remotePath = $ftpFilesPath + $file.Remote
        $localPath = Join-Path $localFilesDir $file.Local
        
        try {
            $webClient.DownloadFile($remotePath, $localPath)
            Write-Host "[УСПЕХ] Скачан: $($file.Local)"
        }
        catch {
            Write-Host "[ОШИБКА] Не удалось скачать $($file.Local): $_"
            $globalError = $true
        }
    }
    
    # Очистка
    $webClient.Dispose()
    $ftpCred = $null
}
# Обработка для протокола SMB
elseif ($protocolFiles -eq "smb") {
    # Параметры SMB
    $smbConfig = $config.smb
    $smbShare = "\\$($smbConfig.server)\$($smbConfig.shareName)"
    $smbFilesPath = "$smbShare\$($smbConfig.filesFullPath)".Replace('/', '\')

    # Получение учетных данных для SMB
    $smbCred = Get-ProtocolCredentials -ProtocolConfig $smbConfig -Protocol "smb"

    # Подключение SMB-шары
    $driveName = "SMBFiles"
    try {
        New-PSDrive -Name $driveName -PSProvider FileSystem -Root $smbFilesPath -Credential $smbCred -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Error "Ошибка подключения к SMB-шаре: $_"
        exit 1
    }

    $smbFiles = @(
        @{Remote = "_soft\7z2409-x64.exe"; Local = "7z2409-x64.exe"},
        @{Remote = "_soft\7zip_opts.reg"; Local = "7zip_opts.reg"},
        @{Remote = "_soft\AkelPad-4.9.8-x64-setup.exe"; Local = "AkelPad-4.9.8-x64-setup.exe"},
        @{Remote = "_soft\HashTab_v6.0.0.34_Setup.exe"; Local = "HashTab_v6.0.0.34_Setup.exe"},
        @{Remote = "_soft\K-Lite_Codec_Pack_1840_Mega.exe"; Local = "K-Lite_Codec_Pack_1840_Mega.exe"},
        @{Remote = "_soft\Unlocker_x64_1.9.2.msi"; Local = "Unlocker_x64_1.9.2.msi"}
    )

    foreach ($file in $smbFiles) {
        $remotePath = "${driveName}:\$($file.Remote)"
        $localPath = Join-Path $localFilesDir $file.Local
        
        try {
            Copy-Item -Path $remotePath -Destination $localPath -Force -ErrorAction Stop
            Write-Host "[УСПЕХ] Скопирован: $($file.Local)"
        }
        catch {
            Write-Host "[ОШИБКА] Не удалось скопировать $($file.Local): $_"
            $globalError = $true
        }
    }

    # Отключение SMB-шары
    try {
        Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Ошибка при отключении SMB-диска: $_"
    }
    
    # Очистка
    $smbCred = $null
}
else {
    Write-Error "Неизвестный протокол для загрузки файлов: $protocolFiles"
    exit 1
}



# ===== 2. СКАЧИВАНИЕ С ПУБЛИЧНОГО HTTP =====
Write-Host "`n===== СКАЧИВАНИЕ С ПУБЛИЧНОГО HTTP ====="

$httpFiles = @(
    @{Name = "WinDirStat-x64.msi"; Url = "https://github.com/windirstat/windirstat/releases/download/release/v2.2.2/WinDirStat-x64.msi"},
    @{Name = "naps2-8.1.4-win-x64.msi"; Url = "https://github.com/cyanfish/naps2/releases/download/v8.1.4/naps2-8.1.4-win-x64.msi"}
)

foreach ($file in $httpFiles) {
    $localPath = Join-Path $localFilesDir $file.Name
    
    try {
        Invoke-WebRequest -Uri $file.Url -OutFile $localPath
        Write-Host "[УСПЕХ] Скачан: $($file.Name)"
    }
    catch {
        Write-Host "[ОШИБКА] Не удалось скачать $($file.Name): $_"
        $globalError = $true
    }
}



# ===== 3. УСТАНОВКА ПРИЛОЖЕНИЙ =====
Write-Host "`n===== УСТАНОВКА ПРИЛОЖЕНИЙ ====="

# Установка AkelPad
try {
    $process = Start-Process "$localFilesDir\AkelPad-4.9.8-x64-setup.exe" -ArgumentList "/S /TYPE=3" -WorkingDirectory $localFilesDir -Wait -PassThru
    if ($process.ExitCode -eq 0) {
        Write-Host "[УСПЕХ] AkelPad установлен"
    }
    else {
        Write-Host "[ОШИБКА] AkelPad завершился с кодом $($process.ExitCode)"
        $globalError = $true
    }
}
catch {
    Write-Host "[ОШИБКА] Ошибка установки AkelPad: $_"
    $globalError = $true
}

# Установка 7-Zip
try {
    $process = Start-Process "$localFilesDir\7z2409-x64.exe" -ArgumentList "/S" -WorkingDirectory $localFilesDir -Wait -PassThru
    if ($process.ExitCode -eq 0) {
        Write-Host "[УСПЕХ] 7-Zip установлен"
    }
    else {
        Write-Host "[ОШИБКА] 7-Zip завершился с кодом $($process.ExitCode)"
        $globalError = $true
    }
}
catch {
    Write-Host "[ОШИБКА] Ошибка установки 7-Zip: $_"
    $globalError = $true
}

# Установка HashTab
try {
    $process = Start-Process "$localFilesDir\HashTab_v6.0.0.34_Setup.exe" -ArgumentList "/S" -WorkingDirectory $localFilesDir -Wait -PassThru
    if ($process.ExitCode -eq 0) {
        Write-Host "[УСПЕХ] HashTab установлен"
    }
    else {
        Write-Host "[ОШИБКА] HashTab завершился с кодом $($process.ExitCode)"
        $globalError = $true
    }
}
catch {
    Write-Host "[ОШИБКА] Ошибка установки HashTab: $_"
    $globalError = $true
}

# Установка K-Lite Codec Pack
try {
    $process = Start-Process "$localFilesDir\K-Lite_Codec_Pack_1840_Mega.exe" -ArgumentList "/verysilent" -WorkingDirectory $localFilesDir -Wait -PassThru
    if ($process.ExitCode -eq 0) {
        Write-Host "[УСПЕХ] K-Lite Codec Pack установлен"
    }
    else {
        Write-Host "[ОШИБКА] K-Lite Codec Pack завершился с кодом $($process.ExitCode)"
        $globalError = $true
    }
}
catch {
    Write-Host "[ОШИБКА] Ошибка установки K-Lite: $_"
    $globalError = $true
}

# Установка WinDirStat
try {
    $process = Start-Process "msiexec.exe" -ArgumentList "/i `"$localFilesDir\WinDirStat-x64.msi`" /qn /norestart" -Wait -PassThru
    if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
        $status = if ($process.ExitCode -eq 3010) { "требует перезагрузки" } else { "успешно" }
        Write-Host "[УСПЕХ] WinDirStat x64 установлен $status"
    }
    else {
        Write-Host "[ОШИБКА] WinDirStat x64 завершился с кодом $($process.ExitCode)"
        $globalError = $true
    }
}
catch {
    Write-Host "[ОШИБКА] Ошибка установки WinDirStat x64: $_"
    $globalError = $true
}

# Установка Unlocker
try {
    $process = Start-Process "msiexec.exe" -ArgumentList "/i `"$localFilesDir\Unlocker_x64_1.9.2.msi`" /qn /norestart" -Wait -PassThru
    if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
        $status = if ($process.ExitCode -eq 3010) { "требует перезагрузки" } else { "успешно" }
        Write-Host "[УСПЕХ] Unlocker установлен $status"
    }
    else {
        Write-Host "[ОШИБКА] Unlocker завершился с кодом $($process.ExitCode)"
        $globalError = $true
    }
}
catch {
    Write-Host "[ОШИБКА] Ошибка установки Unlocker: $_"
    $globalError = $true
}

# Установка NAPS2
try {
    $process = Start-Process "msiexec.exe" -ArgumentList "/i `"$localFilesDir\naps2-8.1.4-win-x64.msi`" /qn /norestart" -Wait -PassThru
    if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
        $status = if ($process.ExitCode -eq 3010) { "требует перезагрузки" } else { "успешно" }
        Write-Host "[УСПЕХ] NAPS2 установлен $status"
    }
    else {
        Write-Host "[ОШИБКА] NAPS2 завершился с кодом $($process.ExitCode)"
        $globalError = $true
    }
}
catch {
    Write-Host "[ОШИБКА] Ошибка установки NAPS2: $_"
    $globalError = $true
}



# ===== 4. НАСТРОЙКА ПАРАМЕТРОВ =====
Write-Host "`n===== НАСТРОЙКА 7-ZIP ====="

try {
    $process = Start-Process "reg.exe" -ArgumentList "import `"$localFilesDir\7zip_opts.reg`"" -Wait -PassThru
    if ($process.ExitCode -eq 0) {
        Write-Host "[УСПЕХ] Настройки 7-Zip применены"
    }
    else {
        Write-Host "[ОШИБКА] Ошибка импорта настроек 7-Zip: код $($process.ExitCode)"
        $globalError = $true
    }
}
catch {
    Write-Host "[ОШИБКА] Ошибка применения настроек 7-Zip: $_"
    $globalError = $true
}



# ===== ОЧИСТКА ЗАГРУЖЕННЫХ ФАЙЛОВ =====
Write-Host "`n===== ОЧИСТКА ЗАГРУЖЕННЫХ ФАЙЛОВ ====="

try {
    if (Test-Path $localFilesDir) {
        Get-ChildItem -Path $localFilesDir -Recurse | Remove-Item -Force -Recurse -ErrorAction Stop
        Write-Host "Содержимое папки очищено: $localFilesDir"
    }
}
catch {
    Write-Host "[ОШИБКА] Не удалось очистить содержимое папки $localFilesDir : $_"
    $globalError = $true
}



# ===== ФИНАЛЬНЫЙ СТАТУС =====
# Если в первом условии при наличии ошибок выполнения какой-либо команды сделать exit 1,
# то весь скрипт перестанет считаться успешно выполненным, лог не будет отправлен на ftp/smb,
# и родительский скрипт тоже не будет считаться успешно выполненным и получит exit 1
if ($globalError) {
    Write-Host "`nВНИМАНИЕ: Некоторые операции завершились с ошибками!"
    exit 0
}
else {
    Write-Host "`nВсе операции успешно завершены!"
    exit 0
}