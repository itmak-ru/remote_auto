# Чтение конфигурации
$configPath = "C:\ProgramData\Remote_Auto\config_vars.json"

if (-not (Test-Path $configPath)) {
    Write-Error "Конфигурационный файл не найден: $configPath"
    exit 1
}

try {
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
}
catch {
    Write-Error "Ошибка чтения конфигурации: $_"
    exit 1
}

# Проверка протоколов
$protocolScripts = $config.protocolScripts
$protocolLogs = $config.protocolLogs

if (-not ($protocolScripts -in @("smb", "ftp")) -or -not ($protocolLogs -in @("smb", "ftp"))) {
    Write-Error "Неверный протокол в конфиге. Допустимые значения: 'smb' или 'ftp'"
    exit 1
}

# Функция для получения учетных данных
function Get-ProtocolCredentials {
    param(
        [Parameter(Mandatory=$true)]
        $ProtocolConfig,
        [Parameter(Mandatory=$true)]
        [string]$ProtocolType,
        [Parameter(Mandatory=$true)]
        [ValidateSet('smb','ftp')]
        [string]$Protocol
    )
    
    $passPlain = $ProtocolConfig.passwordPlain
    $user = $ProtocolConfig.user
    
    # Пути для учетных данных
    $credFolder = "C:\ProgramData\Remote_Auto\creds"
    $credFile = Join-Path $credFolder "cred_${Protocol}_pwd.txt"
    $keyFile = Join-Path $credFolder "encryption_key.bin"

    try {
        $securePass = $null
        
        # 1. Проверка открытого пароля
        if (-not [string]::IsNullOrEmpty($passPlain)) {
            $securePass = ConvertTo-SecureString $passPlain -AsPlainText -Force -ErrorAction Stop
            Write-Host "Используется открытый пароль для $ProtocolType" -ForegroundColor Green
        }
        # 2. Проверка зашифрованного пароля
        elseif ((Test-Path $credFile) -and (Test-Path $keyFile)) {
            try {
                $key = [System.IO.File]::ReadAllBytes($keyFile)
                $encryptedPassword = Get-Content $credFile -ErrorAction Stop
                $securePass = ConvertTo-SecureString -String $encryptedPassword -Key $key -ErrorAction Stop
                Write-Host "Пароль загружен (AES) для $ProtocolType" -ForegroundColor Yellow
            }
            catch {
                Write-Warning "Ошибка дешифровки пароля для $ProtocolType : $_"
                throw "Не удалось получить пароль: ни открытый пароль не задан, ни зашифрованный не прочитан."
            }
        }
        else {
            throw "Пароль не найден: отсутствуют файлы $($credFile) и $($keyFile)."
        }

        # Создание учетных данных
        if ($Protocol -eq 'ftp') {
            return New-Object System.Net.NetworkCredential($user, $securePass)
        }
        else {
            return New-Object System.Management.Automation.PSCredential ($user, $securePass)
        }
    }
    catch {
        Write-Error "Ошибка при работе с паролем для $ProtocolType : $_"
        exit 1
    }
}

# Получение конфигураций
$configScripts = $config.$protocolScripts
$configLogs = $config.$protocolLogs

# Получение учетных данных
$credScripts = Get-ProtocolCredentials -ProtocolConfig $configScripts -ProtocolType "скрипты ($protocolScripts)" -Protocol $protocolScripts
$credLogs = Get-ProtocolCredentials -ProtocolConfig $configLogs -ProtocolType "логи ($protocolLogs)" -Protocol $protocolLogs

# ===== ФОРМИРОВАНИЕ ПУТЕЙ =====
# Для скриптов
if ($protocolScripts -eq "ftp") {
    $remoteScriptsPath = "ftp://$($configScripts.server)/$($configScripts.scriptsFullPath)/" -replace '(?<!:)/{2,}', '/'
}
else {
    $smbScriptsShare = "\\$($configScripts.server)\$($configScripts.shareName)"
    $remoteScriptsPath = "$smbScriptsShare\$($configScripts.scriptsFullPath)".Replace('/', '\')
}

# Для логов
if ($protocolLogs -eq "ftp") {
    $remoteLogsPath = "ftp://$($configLogs.server)/$($configLogs.logsFullPath)/" -replace '(?<!:)/{2,}', '/'
}
else {
    $smbLogsShare = "\\$($configLogs.server)\$($configLogs.shareName)"
    $remoteLogsPath = "$smbLogsShare\$($configLogs.logsFullPath)".Replace('/', '\')
}

# Локальные параметры
$localScriptsDir = "C:\ProgramData\Remote_Auto\scripts"
$localLogsDir = "C:\ProgramData\Remote_Auto\logs"
$localArchiveDir = "C:\ProgramData\Remote_Auto\archives"
$versionHistoryPath = "C:\ProgramData\Remote_Auto\script_history_run_date_all.json"

# Создание локальных директорий
foreach ($dir in ($localScriptsDir, $localLogsDir, $localArchiveDir)) {
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force }
}

# Инициализация истории выполнения
$scriptHistory = @{
    Executions = @()
}

# Загрузка существующей истории
if (Test-Path $versionHistoryPath) {
    try {
        $existingData = Get-Content $versionHistoryPath -Raw | ConvertFrom-Json
        $scriptHistory.Executions = @($existingData.Executions)
    }
    catch {
        Write-Error "Ошибка чтения журнала выполнения: $_"
        exit 1
    }
}

# Получение системной информации
$currentDate = Get-Date -Format "yyyyMMdd"
$osInfo = Get-CimInstance Win32_OperatingSystem
$windowsVersion = $osInfo.Version
$psVersion = $PSVersionTable.PSVersion.ToString()
$computerName = $env:COMPUTERNAME

# Формирование имени целевого скрипта
$targetScriptName = "run_date_all_${currentDate}.ps1"

# Проверка, выполнялся ли скрипт сегодня
$alreadyExecuted = $scriptHistory.Executions | Where-Object { 
    $_.ScriptName -eq $targetScriptName 
}

if ($alreadyExecuted) {
    Write-Host "Скрипт $targetScriptName уже выполнялся. Запуск отменен."
    exit 0
}

# ===== ПРОВЕРКА И ЗАГРУЗКА СКРИПТА =====
$scriptExists = $false
$localScript = Join-Path $localScriptsDir $targetScriptName

if ($protocolScripts -eq "ftp") {
    # Проверка через FTP
    $ftpRequest = [System.Net.FtpWebRequest]::Create($remoteScriptsPath)
    $ftpRequest.Credentials = $credScripts
    $ftpRequest.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory

    try {
        $response = $ftpRequest.GetResponse()
        $streamReader = New-Object IO.StreamReader($response.GetResponseStream())
        $files = $streamReader.ReadToEnd() -split "`r`n"
        $scriptExists = $files -contains $targetScriptName
        $streamReader.Close()
        $response.Close()
    }
    catch {
        Write-Error "Ошибка подключения к FTP (скрипты): $_"
        exit 1
    }

    # Загрузка скрипта
    if ($scriptExists) {
        try {
            $webClient = New-Object System.Net.WebClient
            $webClient.Credentials = $credScripts
            $remoteScript = "${remoteScriptsPath}${targetScriptName}"
            $webClient.DownloadFile($remoteScript, $localScript)
            $webClient.Dispose()
        }
        catch {
            Write-Error "Ошибка загрузки скрипта: $_"
            exit 1
        }
    }
}
else {
    # Работа с SMB
    $driveName = "SMBScriptsDrive_$(Get-Random)"
    try {
        # Подключение сетевого диска
        $null = New-PSDrive -Name $driveName -PSProvider FileSystem -Root $remoteScriptsPath -Credential $credScripts -ErrorAction Stop
        
        $remoteScript = "${driveName}:\$targetScriptName"
        $scriptExists = Test-Path $remoteScript
        
        # Копирование скрипта
        if ($scriptExists) {
            Copy-Item -Path $remoteScript -Destination $localScript -Force
        }
    }
    catch {
        Write-Error "Ошибка работы с SMB (скрипты): $_"
        exit 1
    }
    finally {
        # Отключение диска
        Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
    }
}

if (-not $scriptExists) {
    Write-Host "Скрипт на $currentDate не найден"
    exit 0
}

# ===== ВЫПОЛНЕНИЕ СКРИПТА =====
$logName = "run_date_all_${currentDate}_$(Get-Date -Format 'HHmmss').log"
$localLog = Join-Path $localLogsDir $logName

# Функция логирования
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [switch]$IsError
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    
    if ($IsError) {
        $logEntry = "[ERROR] $logEntry"
        Write-Error $logEntry
    }
    
    try {
        $logEntry | Add-Content $localLog -ErrorAction Stop
    }
    catch {
        Write-Error "Ошибка записи в лог: $_"
    }
}

# Запись информации о запуске
Write-Log "=============================================="
Write-Log "Запуск скрипта ($protocolScripts): $targetScriptName"
Write-Log "Системная информация:"
Write-Log "  ОС: $($osInfo.Caption)"
Write-Log "  Версия Windows: $windowsVersion"
Write-Log "  PowerShell: $psVersion"
Write-Log "  Компьютер: $computerName"
Write-Log "  Дата выполнения: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')"
Write-Log "  Протокол скриптов: $protocolScripts"
Write-Log "  Протокол логов: $protocolLogs"
Write-Log "=============================================="

try {
    # Выполнение скрипта
    $stdOutFile = Join-Path $env:TEMP "stdout_$([Guid]::NewGuid()).log"
    $stdErrFile = Join-Path $env:TEMP "stderr_$([Guid]::NewGuid()).log"
    
    $ps = Start-Process "powershell.exe" -ArgumentList "-File `"$localScript`"" `
        -WindowStyle Hidden `
        -RedirectStandardOutput $stdOutFile `
        -RedirectStandardError $stdErrFile `
        -PassThru -Wait
    
    $output = Get-Content $stdOutFile -Encoding Oem -Raw -ErrorAction SilentlyContinue
    $errorOutput = Get-Content $stdErrFile -Encoding Oem -Raw -ErrorAction SilentlyContinue

    Write-Log "Вывод скрипта:`n$($output)"
    if ($errorOutput) {
        Write-Log "Ошибки:`n$errorOutput" -IsError
    }

    if ($ps.ExitCode -ne 0) {
        throw "Код ошибки: $($ps.ExitCode)"
    }

    # Обновление истории
    $scriptHistory.Executions += [PSCustomObject]@{
        ScriptName = $targetScriptName
        ExecutionDate = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        Computer = $computerName
        Status = "Success"
    }

    # ===== ОТПРАВКА ЛОГА =====
    if ($protocolLogs -eq "ftp") {
        # Выгрузка на FTP
        try {
            $webClient = New-Object System.Net.WebClient
            $webClient.Credentials = $credLogs
            
            $remoteLog = "${remoteLogsPath}$logName"
            $webClient.UploadFile($remoteLog, [System.Net.WebRequestMethods+Ftp]::UploadFile, $localLog)
            $webClient.Dispose()
            
            Write-Log "Лог успешно выгружен на FTP: $remoteLog"
        }
        catch {
            $errMsg = "Ошибка выгрузки лога: $($_.Exception.Message)"
            Write-Log $errMsg -IsError
        }
    }
    else {
        # Отправка через SMB
        $driveName = "SMBLogsDrive_$(Get-Random)"
        try {
            # Подключение сетевого диска
            $null = New-PSDrive -Name $driveName -PSProvider FileSystem -Root $remoteLogsPath -Credential $credLogs -ErrorAction Stop
            
            $remoteLog = "${driveName}:\$logName"
            Copy-Item -Path $localLog -Destination $remoteLog -Force
            
            Write-Log "Лог успешно скопирован на SMB: $remoteLog"
        }
        catch {
            $errMsg = "Ошибка копирования лога: $($_.Exception.Message)"
            Write-Log $errMsg -IsError
        }
        finally {
            # Отключение диска
            Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
        }
    }
}
catch {
    Write-Log "Ошибка выполнения: $($_.Exception.Message)" -IsError
    $scriptHistory.Executions += [PSCustomObject]@{
        ScriptName = $targetScriptName
        ExecutionDate = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        Computer = $computerName
        Status = "Failed"
    }
    exit 1
}
finally {
    # Архивирование
    $archiveName = "run_date_all_${currentDate}_$(Get-Date -Format 'HHmmss').zip"
    Compress-Archive -Path $localScript -DestinationPath (Join-Path $localArchiveDir $archiveName) -Force
    Remove-Item $localScript -Force

    # Сохранение истории
    $scriptHistory | ConvertTo-Json -Depth 3 | Set-Content $versionHistoryPath -Force
    
    Write-Log "Завершено"
}

Write-Host "Скрипт выполнен"