# xiem_install.ps1
# Run as Administrator via ESET Protect software installation task

param(
    [string]$ServerUrl     = "https://xiem.x9.cz",
    [string]$InstallSecret = "",
    [string]$Group         = "rds",
    [string]$InstallDir    = "C:\Program Files\XiemAgent"
)

$ServiceName = "XiemAgent"
$ExePath     = Join-Path $InstallDir "XiemAgent.exe"
$ConfigPath  = Join-Path $InstallDir "appsettings.json"
$LogFile     = "C:\Windows\Temp\xiem-install.log"

function Write-Log {
    param([string]$Msg)
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Msg"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

function Exit-Fail {
    param([string]$Msg)
    Write-Log "ERROR: $Msg"
    exit 1
}

# --- 0. Check admin ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Exit-Fail "Script must run as Administrator"
}

if ([string]::IsNullOrEmpty($InstallSecret)) {
    Exit-Fail "InstallSecret is required. Use: .\xiem_install.ps1 -InstallSecret 'YOUR_SECRET' -Group 'rds'"
}

Write-Log "=== XIEM Agent Install START ==="
Write-Log "Server: $ServerUrl | Group: $Group | Dir: $InstallDir"

# --- 1. Stop and remove existing service ---
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Log "Stopping existing service..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName | Out-Null
    Write-Log "Existing service removed"
}

# --- 2. Create install directory ---
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Log "Created directory: $InstallDir"
}

# --- 3. Download EXE ---
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
Write-Log "Downloading XiemAgent.exe..."
try {
    Invoke-WebRequest -Uri "$ServerUrl/api/download/agent" `
                      -OutFile $ExePath `
                      -UseBasicParsing `
                      -ErrorAction Stop
    Write-Log "Downloaded: $ExePath"
} catch {
    Exit-Fail "Failed to download agent: $_"
}

# --- 4. Register agent, get token ---
Write-Log "Registering agent..."
$regBody = @{
    install_secret = $InstallSecret
    hostname       = $env:COMPUTERNAME
    group          = $Group
    agent_version  = "1.1.0"
} | ConvertTo-Json

try {
    $regResp = Invoke-RestMethod -Uri "$ServerUrl/api/agent/register" `
                                 -Method POST `
                                 -Body $regBody `
                                 -ContentType "application/json" `
                                 -ErrorAction Stop
    $token = $regResp.token
    if ([string]::IsNullOrEmpty($token)) {
        Exit-Fail "Registration returned empty token"
    }
    Write-Log "Registration successful"
} catch {
    Exit-Fail "Registration failed: $_"
}

# --- 5. Write appsettings.json ---
$config = @{
    Xiem = @{
        BaseUrl       = $ServerUrl
        Token         = $token
        InstallSecret = ""
        Group         = $Group
    }
    Logging = @{
        LogLevel = @{
            Default                      = "Information"
            "Microsoft.Hosting.Lifetime" = "Information"
        }
        EventLog = @{
            LogLevel = @{ Default = "Information" }
        }
    }
} | ConvertTo-Json -Depth 5

Set-Content -Path $ConfigPath -Value $config -Encoding UTF8
Write-Log "Config written: $ConfigPath"

# --- 6. Register Windows Service ---
Write-Log "Creating Windows Service..."
$scResult = sc.exe create $ServiceName binPath= "`"$ExePath`"" start= auto DisplayName= "XIEM Agent"
if ($LASTEXITCODE -ne 0) {
    Exit-Fail "sc create failed: $scResult"
}
sc.exe description $ServiceName "X9 Intrusion and Event Monitor Agent" | Out-Null
Write-Log "Service created"

# --- 7. Start service ---
Write-Log "Starting service..."
Start-Service -Name $ServiceName -ErrorAction Stop
Start-Sleep -Seconds 3

$svc = Get-Service -Name $ServiceName
if ($svc.Status -ne "Running") {
    Exit-Fail "Service failed to start, status: $($svc.Status)"
}

Write-Log "Service running"
Write-Log "=== XIEM Agent Install COMPLETE ==="
exit 0
