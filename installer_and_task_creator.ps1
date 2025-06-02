#Requires -RunAsAdministrator

# ======================== КОНФИГУРАЦИЯ ========================
$scriptsFolder = $PSScriptRoot
$tasksFolder = "RemoteAuto"
$admin_username = "local_admin_runner"
$targetRootFolder = "C:\ProgramData\Remote_Auto"
$targetScriptsFolder = "$targetRootFolder\start_ps1"

# === ОПЦИЯ: Пароль для локального администратора в открытом виде ===
#$plain_password = "Super-Secret5-Passw0rd"

# ======================== ПОДГОТОВКА ПАПКИ ДЛЯ СКРИПТОВ ========================
Write-Host "`n=== ПОДГОТОВКА ПАПКИ ДЛЯ СКРИПТОВ ===" -ForegroundColor Yellow

# Создаем корневую папку и подпапку для скриптов
try {
    New-Item -Path $targetScriptsFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
    Write-Host "Папка для скриптов создана: $targetScriptsFolder" -ForegroundColor Green
}
catch {
    Write-Error "ОШИБКА: Не удалось создать целевую папку для скриптов: $_"
    exit 1
}

# Копируем скрипты в целевую папку
try {
    Get-ChildItem -Path $scriptsFolder -Filter "run_*.ps1" -ErrorAction Stop | ForEach-Object {
        $destPath = Join-Path $targetScriptsFolder $_.Name
        Copy-Item -Path $_.FullName -Destination $destPath -Force -ErrorAction Stop
        Write-Host "Скрипт скопирован: $($_.Name) -> $destPath" -ForegroundColor Green
    }
    
    # Копируем конфигурационный файл
    Copy-Item -Path "$PSScriptRoot\config_vars.json" -Destination "$targetRootFolder\config_vars.json" -Force
    Write-Host "Файл конфигурации скопирован: config_vars.json -> $targetRootFolder" -ForegroundColor Green
    

    # Обновляем рабочую папку скриптов
    $scriptsFolder = $targetScriptsFolder
}
catch {
    Write-Error "ОШИБКА: Не удалось скопировать скрипты в целевую папку: $_"
    exit 1
}

# ======================== УСТАНОВКА ПРАВ ДОСТУПА НА ПАПКУ ========================
try {
    Write-Host "`n=== УСТАНОВКА ПРАВ ДОСТУПА ===" -ForegroundColor Yellow
    Write-Host "Устанавливаем права на папку: $targetRootFolder" -ForegroundColor Cyan
    
    icacls $targetRootFolder /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" | Out-Null
    
    Write-Host "Права доступа успешно установлены!" -ForegroundColor Green
    Write-Host "Доступ разрешен только для: Administrators (S-1-5-32-544) и SYSTEM (S-1-5-18)" -ForegroundColor Cyan
}
catch {
    Write-Error "ОШИБКА: Не удалось установить права доступа: $_"
    exit 1
}

# ======================== ВЫБОР УЧЕТНОЙ ЗАПИСИ ========================
Write-Host "`n=== ВЫБОР УЧЕТНОЙ ЗАПИСИ ===" -ForegroundColor Yellow
Write-Host "1. NT AUTHORITY\SYSTEM (Локальная система)" -ForegroundColor Yellow
Write-Host "2. Создать отдельного администратора $admin_username (рекомендуется)" -ForegroundColor Yellow

$accountChoice = Read-Host "Введите номер (по умолчанию 2)"
if (-not $accountChoice) { $accountChoice = 2 }

$taskUser = $null
$passwordText = $null

if ($accountChoice -eq 2) {
    # Функция безопасного ввода пароля
    function Get-SecurePassword {
        param([Parameter(Mandatory=$true)][string]$Prompt)
        do {
            Write-Host $Prompt -ForegroundColor Cyan -NoNewline
            $pass1 = Read-Host -AsSecureString
            
            if (-not $pass1 -or $pass1.Length -eq 0) {
                Write-Host "Пароль не может быть пустым!" -ForegroundColor Red
                continue
            }
            
            Write-Host "Повторите пароль: " -ForegroundColor Cyan -NoNewline
            $pass2 = Read-Host -AsSecureString
            
            $plain1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass1))
            $plain2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass2))
            
            if ($plain1 -ne $plain2) {
                Write-Host "Пароли не совпадают!" -ForegroundColor Red
            }
            else {
                return $pass1
            }
            
            $plain1 = $null; $plain2 = $null; [GC]::Collect()
        } while ($true)
    }

    if ($plain_password) {
        Write-Host "`nИспользуется пароль из переменной" -ForegroundColor Yellow
        $admin_password = ConvertTo-SecureString $plain_password -AsPlainText -Force
    }
    else {
        Write-Host "`n=== СОЗДАНИЕ АДМИНИСТРАТОРА ===" -ForegroundColor Yellow
        $admin_password = Get-SecurePassword -Prompt "Введите пароль для $admin_username`: "
    }

    try {
        # Настраиваем политику срока жизни паролей (для систем без домена)
        net accounts /maxpwage:unlimited | Out-Null

        # Создание/обновление пользователя
        if (-not (Get-LocalUser -Name $admin_username -ErrorAction SilentlyContinue)) {
            New-LocalUser -Name $admin_username -Password $admin_password `
                -AccountNeverExpires -PasswordNeverExpires -ErrorAction Stop
        }
        else {
            Set-LocalUser -Name $admin_username -Password $admin_password -PasswordNeverExpires $true -ErrorAction Stop
        }

        # Скрытие пользователя
        $regPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
        if (-not (Test-Path $regPath)) { 
            New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null 
        }
        Set-ItemProperty -Path $regPath -Name $admin_username -Value 0 -Type DWord -Force -ErrorAction Stop

        # Добавление в группу администраторов
        $adminGroup = Get-LocalGroup -SID "S-1-5-32-544" -ErrorAction Stop
        if (-not (Get-LocalGroupMember -Group $adminGroup -Member $admin_username -ErrorAction SilentlyContinue)) {
            Add-LocalGroupMember -Group $adminGroup -Member $admin_username -ErrorAction Stop
        }
        
        Write-Host "`nАккаунт $admin_username успешно создан!" -ForegroundColor Green
    }
    catch {
        Write-Error "ОШИБКА создания аккаунта: $_"
        exit 1
    }

    $taskUser = "$env:COMPUTERNAME\$admin_username"
    
    if ($plain_password) {
        $passwordText = $plain_password
    }
    else {
        $passwordText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($admin_password))
    }
}
else {
    $taskUser = "NT AUTHORITY\SYSTEM"
}

Write-Host "`nЗадачи будут запускаться от имени: $taskUser" -ForegroundColor Green

# ======================== НАСТРОЙКА ЗАДАЧ ПЛАНИРОВЩИКА ========================
Write-Host "`n=== СОЗДАНИЕ ЗАДАЧ ПЛАНИРОВЩИКА ===" -ForegroundColor Yellow

# Общие параметры задач
$commonSettings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 5) `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 90)

$powerShellPath = (Get-Process -Id $PID).Path

# Создание папки в планировщике
try {
    $scheduleObject = New-Object -ComObject Schedule.Service
    $scheduleObject.Connect()
    $rootFolder = $scheduleObject.GetFolder("\")
    $rootFolder.CreateFolder($tasksFolder) | Out-Null
    Write-Host "Папка задач создана: \$tasksFolder" -ForegroundColor Cyan
}
catch {
    Write-Warning "Папка $tasksFolder уже существует: $_"
}

# ======================== ФУНКЦИЯ РЕГИСТРАЦИИ ЗАДАЧ ========================
function Register-Task {
    param(
        [string]$TaskName,
        [string]$ScriptFile,
        [array]$Triggers,
        [string]$Description
    )
    
    $scriptPath = Join-Path $scriptsFolder $ScriptFile
    if (-not (Test-Path $scriptPath)) {
        Write-Error "Скрипт $ScriptFile не найден в $scriptsFolder!"
        return $null
    }

    $action = New-ScheduledTaskAction -Execute $powerShellPath `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""

    # Удаляем существующую задачу
    $taskPath = "\$tasksFolder\"
    if (Get-ScheduledTask -TaskName $TaskName -TaskPath $taskPath -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath $taskPath -Confirm:$false
        Write-Host "Существующая задача '$TaskName' удалена" -ForegroundColor Yellow
    }

    # Параметры регистрации
    $params = @{
        TaskName    = $TaskName
        TaskPath    = $taskPath
        Action      = $action
        Trigger     = $Triggers
        Settings    = $commonSettings
        Description = $Description
        RunLevel    = "Highest"
        ErrorAction = "Stop"
    }

    # Добавляем учетные данные для администратора
    if ($accountChoice -eq 2) {
        $params['User'] = $taskUser
        $params['Password'] = $passwordText
    }

    else {
    # Указываем SYSTEM для выбора 1
    $params['User'] = "NT AUTHORITY\SYSTEM"
    }

    # Регистрируем задачу
    try {
        $task = Register-ScheduledTask @params
        Write-Host "Задача '$TaskName' успешно создана" -ForegroundColor Green
        return $task
    }
    catch {
        Write-Error "ОШИБКА создания задачи $TaskName : $_"
        return $null
    }
}

# === ИНТЕРВАЛЫ И ЗАДЕРЖКИ ДЛЯ ЗАДАЧ ===
$randomDelayForAll = "PT15M"   # до 15 минут случайной задержки для задачи "For All"
$randomDelayPCSpecific = "PT15M"    # до 15 минут случайной задержки для задачи "PC Specific"
$randomDelayCompDate = "PT15M"   # до 15 минут случайной задержки для "Computer and Date"
$randomDelayDateAll = "PT15M"    # до 15 минут случайной задержки для "Date All"
$startupDelayForAll = "PT1M"     # 1 минута для задачи "For All"
$startupDelayPCSpecific = "PT10M" # 10 минут для задачи "PC Specific"
$startupDelayCompDate = "PT15M"   # 15 минут для задачи "Computer and Date"
$startupDelayDateAllTask = "PT5M" # 5 минут для задачи "Date All"

# ======================== СОЗДАНИЕ ЗАДАЧ ========================
Write-Host "`nСоздаем задачи..." -ForegroundColor Cyan

# Общая функция для создания триггеров
function Create-Triggers {
    param(
        [string[]]$Times,
        [string]$RandomDelay,
        [string]$StartupDelay
    )
    
    $triggers = @()
    
    # Триггер при запуске системы
    $startupTrigger = New-ScheduledTaskTrigger -AtStartup
    $startupTrigger.Delay = $StartupDelay
    $triggers += $startupTrigger
    
    # Периодические триггеры
    foreach ($time in $Times) {
        $trigger = New-ScheduledTaskTrigger -Daily -At $time
        $trigger.RandomDelay = $RandomDelay
        $triggers += $trigger
    }
    
    return $triggers
}

# Задача 1: Computer and Date
$triggerTimes1 = @("00:00", "02:00", "04:00", "06:00", "08:00", "10:00", 
                  "12:00", "14:00", "16:00", "18:00", "20:00", "22:00")

$allTriggers1 = Create-Triggers -Times $triggerTimes1 `
    -RandomDelay $randomDelayCompDate `
    -StartupDelay $startupDelayCompDate

Register-Task -TaskName "RemoteAuto Daily Run (Computer and Date)" `
    -ScriptFile "run_comp_date.ps1" `
    -Triggers $allTriggers1 `
    -Description "Запуск при старте системы (с задержкой $startupDelayCompDate) и каждые 2 часа в 00 минут со случайной задержкой $randomDelayCompDate"

# Задача 2: Date All
$triggerTimes2 = @("01:30", "03:30", "05:30", "07:30", "09:30", "11:30",
                  "13:30", "15:30", "17:30", "19:30", "21:30", "23:30")

$allTriggers2 = Create-Triggers -Times $triggerTimes2 `
    -RandomDelay $randomDelayDateAll `
    -StartupDelay $startupDelayDateAllTask

Register-Task -TaskName "RemoteAuto Daily Run (Date All)" `
    -ScriptFile "run_date_all.ps1" `
    -Triggers $allTriggers2 `
    -Description "Запуск при старте системы (с задержкой $startupDelayDateAllTask) и каждые 2 часа в 30 минут со случайной задержкой $randomDelayDateAll"

# Задача 3: For All
$triggerTimes3 = @("00:30", "02:30", "04:30", "06:30", "08:30", "10:30", 
                  "12:30", "14:30", "16:30", "18:30", "20:30", "22:30")

$allTriggers3 = Create-Triggers -Times $triggerTimes3 `
    -RandomDelay $randomDelayForAll `
    -StartupDelay $startupDelayForAll

Register-Task -TaskName "RemoteAuto Version Run (For All)" `
    -ScriptFile "run_for_all_ver.ps1" `
    -Triggers $allTriggers3 `
    -Description "Запуск при старте системы (с задержкой $startupDelayForAll) и каждые 2 часа в 30 минут со случайной задержкой $randomDelayForAll"

# Задача 4: PC Specific
$triggerTimes4 = @("01:00", "03:00", "05:00", "07:00", "09:00", "11:00",
                  "13:00", "15:00", "17:00", "19:00", "21:00", "23:00")

$allTriggers4 = Create-Triggers -Times $triggerTimes4 `
    -RandomDelay $randomDelayPCSpecific `
    -StartupDelay $startupDelayPCSpecific

Register-Task -TaskName "RemoteAuto Version Run (PC Specific)" `
    -ScriptFile "run_pc_ver.ps1" `
    -Triggers $allTriggers4 `
    -Description "Запуск при старте системы (с задержкой $startupDelayPCSpecific) и каждые 2 часа в 00 минут со случайной задержкой $randomDelayPCSpecific"

# ======================== ЗАВЕРШЕНИЕ ========================
# Очистка конфиденциальных данных
if ($passwordText) {
    Write-Host "Очищаем следы пароля из памяти..." -ForegroundColor DarkGray
    $passwordText = $null
    [GC]::Collect()
}

if (Get-Variable -Name plain_password -ErrorAction SilentlyContinue) {
    Remove-Variable -Name plain_password -Force -ErrorAction SilentlyContinue
    [GC]::Collect()
    Write-Host "Переменная `$plain_password удалена из памяти" -ForegroundColor Green
}

Write-Host "`n=== ИТОГИ ===" -ForegroundColor Green
Write-Host "Успешно создано 4 задачи в папке: \$tasksFolder" -ForegroundColor Cyan
Write-Host "Скрипты расположены в: $scriptsFolder" -ForegroundColor Cyan

if ($accountChoice -eq 2) {
    Write-Host "`n=== ВАЖНАЯ ИНФОРМАЦИЯ ===" -ForegroundColor Red
    Write-Host "Пароль для учетной записи $admin_username НЕ СОХРАНЕН в скрипте!" -ForegroundColor Red
    
    if (-not $plain_password) {
        Write-Host "Обязательно сохраните пароль в надежном месте!" -ForegroundColor Red
        Write-Host "Без него задачи не смогут запускаться!" -ForegroundColor Red
    }
}

Write-Host "`nНастройка задач планировщика успешно завершена!" -ForegroundColor Green
Write-Host "Для проверки откройте: taskschd.msc -> Папка \$tasksFolder" -ForegroundColor Cyan

# ======================== ПРОВЕРКА УЧЕТНЫХ ДАННЫХ ========================
Write-Host "`n=== ПРОВЕРКА УЧЕТНЫХ ДАННЫХ ===" -ForegroundColor Yellow

$credsFolder = "$targetRootFolder\creds"
$credFtpPath = Join-Path $credsFolder "cred_ftp_pwd.txt"
$credSmbPath = Join-Path $credsFolder "cred_smb_pwd.txt"
$encKeyPath = Join-Path $credsFolder "encryption_key.bin"

$filesMissing = $false

# Проверяем наличие хотя бы одного файла учетных данных
$anyCredFileExists = (Test-Path $credFtpPath) -or (Test-Path $credSmbPath)

if (-not $anyCredFileExists) {
    Write-Host "Отсутствуют файлы учетных данных!" -ForegroundColor Red
    Write-Host "Не найден ни один из файлов: cred_ftp_pwd.txt или cred_smb_pwd.txt" -ForegroundColor Red
    $filesMissing = $true
}

if (-not (Test-Path $encKeyPath)) {
    Write-Host "Файл ключа шифрования не найден: $encKeyPath" -ForegroundColor Red
    $filesMissing = $true
}

if ($filesMissing) {
    Write-Host "`n=== ТРЕБУЕТСЯ ДЕЙСТВИЕ ===" -ForegroundColor Red
    Write-Host "Необходимые файлы учетных данных отсутствуют!" -ForegroundColor Red
    
    $generatorScript = Join-Path $PSScriptRoot "password_credfile_generator.ps1"
    
    if (Test-Path $generatorScript) {
        # Запрос на генерацию пароля
        $generateChoice = Read-Host "`nСгенерировать пароль для FTP/SMB? (Y/N)"
        if ($generateChoice -eq 'Y' -or $generateChoice -eq 'y') {
            try {
                Write-Host "Запуск генератора учетных данных..." -ForegroundColor Cyan
                & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$generatorScript`"
                Write-Host "`nГенерация учетных данных завершена!" -ForegroundColor Green
                
                # Повторная проверка файлов
                $anyCredFileExists = (Test-Path $credFtpPath) -or (Test-Path $credSmbPath)
                
                if ($anyCredFileExists -and (Test-Path $encKeyPath)) {
                    Write-Host "Файлы учетных данных успешно созданы" -ForegroundColor Green
                }
                else {
                    Write-Host "`nОШИБКА: Не все файлы учетных данных созданы!" -ForegroundColor Red
                    Write-Host "Пожалуйста, создайте их вручную с помощью скрипта: $generatorScript" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "`nОШИБКА при запуске генератора: $_" -ForegroundColor Red
                Write-Host "Запустите скрипт вручную: $generatorScript" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "`nДля создания файлов учетных данных выполните:" -ForegroundColor Yellow
            Write-Host "1. Запустите скрипт: $generatorScript" -ForegroundColor Yellow
            Write-Host "2. Следуйте инструкциям по вводу данных FTP/SMB" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "Скрипт для создания учетных данных не найден: $generatorScript" -ForegroundColor Red
        Write-Host "Убедитесь, что файл password_credfile_generator.ps1 находится в папке: $PSScriptRoot" -ForegroundColor Yellow
    }
}
else {
    Write-Host "Файлы учетных данных присутствуют" -ForegroundColor Green
}