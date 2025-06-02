#Requires -RunAsAdministrator

$credFolder = "C:\ProgramData\Remote_Auto\creds"
$credFileFtp = Join-Path $credFolder "cred_ftp_pwd.txt"
$credFileSmb = Join-Path $credFolder "cred_smb_pwd.txt"
$keyFile = Join-Path $credFolder "encryption_key.bin"

# =============================================================================
# ПРЕДОПРЕДЕЛЕННЫЕ ПАРОЛИ (раскомментируйте при необходимости)
# Рекомендуется использовать только для тестовых сред!
# =============================================================================
# $predefinedFtpPassword = "Your_FTP_Password_Here"
# $predefinedSmbPassword = "Your_SMB_Password_Here"
# =============================================================================

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
            [string]$PredefinedPassword = $null
        )
        
        if (Test-Path $FilePath) {
            $choice = Read-Host "Файл пароля для $ServiceName уже существует. Перезаписать? (Y/N)"
            if ($choice -notmatch '^[Yy]$') {
                Write-Host "Обновление пароля $ServiceName пропущено."
                return
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

    # Обработка FTP
    $generateFtp = Read-Host "Сгенерировать пароль для FTP? (Y/N)"
    if ($generateFtp -match '^[Yy]$') {
        # Раскомментируйте следующую строку для использования предопределенного пароля FTP
        # Update-PasswordFile -FilePath $credFileFtp -ServiceName "FTP" -Key $key -PredefinedPassword $predefinedFtpPassword
        Update-PasswordFile -FilePath $credFileFtp -ServiceName "FTP" -Key $key
    }

    # Обработка SMB
    $generateSmb = Read-Host "Сгенерировать пароль для SMB? (Y/N)"
    if ($generateSmb -match '^[Yy]$') {
        # Раскомментируйте следующую строку для использования предопределенного пароля SMB
        # Update-PasswordFile -FilePath $credFileSmb -ServiceName "SMB" -Key $key -PredefinedPassword $predefinedSmbPassword
        Update-PasswordFile -FilePath $credFileSmb -ServiceName "SMB" -Key $key
    }

    if (($generateFtp -notmatch '^[Yy]$') -and ($generateSmb -notmatch '^[Yy]$')) {
        Write-Host "Операция отменена: не выбран ни один сервис для генерации пароля."
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
        
        if (Test-Path variable:predefinedSmbPassword) {
            $predefinedSmbPassword = $null
            Remove-Variable predefinedSmbPassword -ErrorAction SilentlyContinue
        }
        
        # Очистка временных переменных
        $generateFtp = $null
        $generateSmb = $null
        $credFolder = $null
        $credFileFtp = $null
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