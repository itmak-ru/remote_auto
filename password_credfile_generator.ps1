[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]$PassFTP,

    [Parameter(Mandatory=$false)]
    [string]$PassFTPS,

    [Parameter(Mandatory=$false)]
    [string]$PassSMB
)

# Проверяем, есть ли у нас права администратора
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "`nСкрипт необходимо запускать с правами администратора" -ForegroundColor Red
    exit 1
}

$silentMode = $PSBoundParameters.ContainsKey('PassFTP') -or $PSBoundParameters.ContainsKey('PassFTPS') -or $PSBoundParameters.ContainsKey('PassSMB')

$credFolder = "C:\ProgramData\Remote_Auto\creds"
$credFileFtp = Join-Path $credFolder "cred_ftp_pwd.txt"
$credFileFtps = Join-Path $credFolder "cred_ftps_pwd.txt"
$credFileSmb = Join-Path $credFolder "cred_smb_pwd.txt"
$keyFile = Join-Path $credFolder "encryption_key.bin"

try {
    # Создание папки и установка прав доступа
    if (-not (Test-Path $credFolder)) {
        New-Item -Path $credFolder -ItemType Directory -Force | Out-Null
        icacls $credFolder /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" | Out-Null
    }

    # Генерация/загрузка ключа
    if (-not (Test-Path $keyFile)) {
        try {
            $key = New-Object Byte[] 32
            [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($key)
            [System.IO.File]::WriteAllBytes($keyFile, $key)
            icacls $keyFile /grant:r "*S-1-5-32-544:F" /grant:r "NT AUTHORITY\SYSTEM:F" | Out-Null
        }
        catch {
            Write-Error "Ошибка создания ключа: $_"
            exit 1
        }
    }
    else {
        $key = [System.IO.File]::ReadAllBytes($keyFile)
    }

    # Функция создания/обновления файла с паролем
    function Update-PasswordFile {
        param (
            [string]$FilePath,
            [string]$ServiceName,
            [byte[]]$Key,
            [string]$PredefinedPassword = $null,
            [switch]$Silent = $false
        )
        
        if (Test-Path $FilePath) {
            if (-not $Silent) {
                $choice = Read-Host "Файл пароля для $ServiceName уже существует. Перезаписать? (Y/N)"
                if ($choice -notmatch '^[Yy]$') {
                    Write-Host "Обновление пароля $ServiceName пропущено."
                    return
                }
            }
            else {
                Write-Host "Файл пароля для $ServiceName будет перезаписан (silent режим)."
            }
        }

        try {
            $securePassword = $null
            $cleanupRequired = $false
            
            if (-not [string]::IsNullOrEmpty($PredefinedPassword)) {
                # Использовать предопределенный пароль
                $securePassword = ConvertTo-SecureString $PredefinedPassword -AsPlainText -Force
                $cleanupRequired = $true
                Write-Host "Использован предопределенный пароль для $ServiceName"
            }
            else {
                # Запросить пароль у пользователя
                $securePassword = Read-Host "Введите пароль для $ServiceName" -AsSecureString
            }

            $encryptedData = ConvertFrom-SecureString -SecureString $securePassword -Key $Key
            $encryptedData | Out-File $FilePath -Force
            icacls $FilePath /grant:r "*S-1-5-32-544:F" /grant:r "NT AUTHORITY\SYSTEM:F" | Out-Null
            Write-Host "Файл пароля для $ServiceName успешно создан/обновлен."
        }
        catch {
            Write-Error "Ошибка при работе с файлом пароля для $ServiceName : $_"
            exit 1
        }
        finally {
            # Очистка конфиденциальных данных из памяти
            if ($securePassword) {
                $securePassword.Dispose()
                $securePassword = $null
            }
            if ($cleanupRequired) {
                # Очищаем переданный пароль внутри функции
                $PredefinedPassword = $null
            }
        }
    }

    # Флаги обработки сервисов
    $ftpProcessed = $false
    $ftpsProcessed = $false
    $smbProcessed = $false

    if ($silentMode) {
        Write-Host "`nЗапуск в silent режиме" -ForegroundColor Cyan

        # Обработка FTP
        if ($PSBoundParameters.ContainsKey('PassFTP')) {
            if (-not [string]::IsNullOrEmpty($PassFTP)) {
                Update-PasswordFile -FilePath $credFileFtp -ServiceName "FTP" -Key $key -PredefinedPassword $PassFTP -Silent
                $ftpProcessed = $true
            }
            else {
                Write-Error "Пароль FTP не может быть пустым в silent режиме"
                exit 1
            }
        }

        # Обработка FTPS
        if ($PSBoundParameters.ContainsKey('PassFTPS')) {
            if (-not [string]::IsNullOrEmpty($PassFTPS)) {
                Update-PasswordFile -FilePath $credFileFtps -ServiceName "FTPS" -Key $key -PredefinedPassword $PassFTPS -Silent
                $ftpsProcessed = $true
            }
            else {
                Write-Error "Пароль FTPS не может быть пустым в silent режиме"
                exit 1
            }
        }

        # Обработка SMB
        if ($PSBoundParameters.ContainsKey('PassSMB')) {
            if (-not [string]::IsNullOrEmpty($PassSMB)) {
                Update-PasswordFile -FilePath $credFileSmb -ServiceName "SMB" -Key $key -PredefinedPassword $PassSMB -Silent
                $smbProcessed = $true
            }
            else {
                Write-Error "Пароль SMB не может быть пустым в silent режиме"
                exit 1
            }
        }
    }
    else {
        # Интерактивный режим
        # Обработка FTP
        if (-not [string]::IsNullOrEmpty($predefinedFtpPassword)) {
            Write-Host "`nОбнаружен предопределенный пароль FTP. Автоматическая генерация файла." -ForegroundColor Green
            Update-PasswordFile -FilePath $credFileFtp -ServiceName "FTP" -Key $key -PredefinedPassword $predefinedFtpPassword
            $ftpProcessed = $true
        }
        else {
            $generateFtp = Read-Host "`nСгенерировать пароль для FTP? (Y/N)"
            if ($generateFtp -match '^[Yy]$') {
                Update-PasswordFile -FilePath $credFileFtp -ServiceName "FTP" -Key $key
                $ftpProcessed = $true
            }
        }

        # Обработка FTPS
        if (-not [string]::IsNullOrEmpty($predefinedFtpsPassword)) {
            Write-Host "`nОбнаружен предопределенный пароль FTPS. Автоматическая генерация файла." -ForegroundColor Green
            Update-PasswordFile -FilePath $credFileFtps -ServiceName "FTPS" -Key $key -PredefinedPassword $predefinedFtpsPassword
            $ftpsProcessed = $true
        }
        else {
            $generateFtps = Read-Host "`nСгенерировать пароль для FTPS? (Y/N)"
            if ($generateFtps -match '^[Yy]$') {
                Update-PasswordFile -FilePath $credFileFtps -ServiceName "FTPS" -Key $key
                $ftpsProcessed = $true
            }
        }

        # Обработка SMB
        if (-not [string]::IsNullOrEmpty($predefinedSmbPassword)) {
            Write-Host "`nОбнаружен предопределенный пароль SMB. Автоматическая генерация файла." -ForegroundColor Green
            Update-PasswordFile -FilePath $credFileSmb -ServiceName "SMB" -Key $key -PredefinedPassword $predefinedSmbPassword
            $smbProcessed = $true
        }
        else {
            $generateSmb = Read-Host "`nСгенерировать пароль для SMB? (Y/N)"
            if ($generateSmb -match '^[Yy]$') {
                Update-PasswordFile -FilePath $credFileSmb -ServiceName "SMB" -Key $key
                $smbProcessed = $true
            }
        }
    }

    if (-not ($ftpProcessed -or $ftpsProcessed -or $smbProcessed)) {
        Write-Host "Операция отменена: не выбран ни один сервис для генерации пароля."
    }
    else {
        Write-Host "`nОперации завершены успешно" -ForegroundColor Green
    }
}
finally {
    # Интенсивная очистка конфиденциальных данных из памяти
    try {
        # Очистка ключа шифрования
        if ($key) {
            [Array]::Clear($key, 0, $key.Length)
            $key = $null
        }
        
        # Очистка предопределенных паролей
        if (Test-Path variable:predefinedFtpPassword) {
            $predefinedFtpPassword = $null
            Remove-Variable predefinedFtpPassword -ErrorAction SilentlyContinue
        }

        if (Test-Path variable:predefinedFtpsPassword) {
            $predefinedFtpsPassword = $null
            Remove-Variable predefinedFtpsPassword -ErrorAction SilentlyContinue
        }
        
        if (Test-Path variable:predefinedSmbPassword) {
            $predefinedSmbPassword = $null
            Remove-Variable predefinedSmbPassword -ErrorAction SilentlyContinue
        }
        
        # Очистка параметров silent режима
        if (Test-Path variable:PassFTP) {
            $PassFTP = $null
            Remove-Variable PassFTP -ErrorAction SilentlyContinue
        }

        if (Test-Path variable:PassFTPS) {
            $PassFTPS = $null
            Remove-Variable PassFTPS -ErrorAction SilentlyContinue
        }

        if (Test-Path variable:PassSMB) {
            $PassSMB = $null
            Remove-Variable PassSMB -ErrorAction SilentlyContinue
        }
        
        # Очистка временных переменных
        $generateFtp = $null
        $generateFtps = $null
        $generateSmb = $null
        $credFolder = $null
        $credFileFtp = $null
        $credFileFtps = $null
        $credFileSmb = $null
        $keyFile = $null
        
        # Принудительный вызов сборщика мусора
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
    catch {
        Write-Warning "Ошибка при очистке памяти: $_"
    }
}