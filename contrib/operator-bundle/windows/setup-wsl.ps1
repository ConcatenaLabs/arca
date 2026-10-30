#Requires -RunAsAdministrator
<#
.SYNOPSIS
  The Windows side of an Arca operator bundle: a WSL2 distro of Ubuntu 24.04
  with systemd, the bundle's public ports reachable from outside, and the
  distro started at boot and kept running.

.DESCRIPTION
  Run it in an elevated PowerShell, as the Windows user the bundle runs under:

    powershell -ExecutionPolicy Bypass -File setup-wsl.ps1

  Every step can run again: what is done is found done. It then prints the two
  commands that install the bundle inside the distro (install.sh, in the same
  directory of ConcatenaLabs/arca as this script).

  What it does, in order:
    1. WSL2: installs it when missing (a restart may be needed; run the script
       again after it).
    2. The distro: Ubuntu 24.04's WSL image from cloud-images.ubuntu.com,
       checked against its published SHA256SUMS, imported as -Distro into
       -InstallDir, with systemd on.
    3. %UserProfile%\.wslconfig: the VM never shuts down for being idle, and,
       where Windows supports it (Windows 11 22H2 or later), mirrored
       networking, so the distro's ports are the host's.
    4. The ports: Windows Firewall rules (and Hyper-V firewall rules in
       mirrored mode) for the two Lightning gateways and Caddy's 80 and 443;
       in NAT mode, a port proxy from the host to the distro, renewed at every
       start because the distro's address changes.
    5. Start at boot: a scheduled task, run whether the user is logged on or
       not, that starts the distro (systemd then starts the bundle) and keeps
       it running.
#>
[CmdletBinding()]
param(
  [string]$Distro = 'ArcaBundle',
  [string]$InstallDir = (Join-Path $env:SystemDrive 'ArcaBundle'),
  # The ports peers and wallets reach: SeqLN, Core Lightning, and Caddy's
  # HTTP (certificates) and HTTPS (the operator and the Bitcoin ark). They
  # must match SEQLN_PORT and CLN_PORT in bundle.env.
  [int[]]$Ports = @(9835, 9935, 80, 443),
  # NAT forces the port proxy even where mirrored networking is available.
  [ValidateSet('auto', 'mirrored', 'nat')] [string]$Networking = 'auto'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Step([string]$what) { Write-Host "`n=== $what ===" }
function Say([string]$what) { Write-Host "  $what" }
function Wsl([string[]]$argv) {
  # wsl.exe writes UTF-16; read it as such.
  $old = [Console]::OutputEncoding
  [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
  try { $out = & wsl.exe @argv 2>&1 | Out-String } finally { [Console]::OutputEncoding = $old }
  if ($LASTEXITCODE -ne 0) { throw "wsl $($argv -join ' ') failed ($LASTEXITCODE): $out" }
  return $out.Replace("`0", '')
}
function InDistro([string]$script) {
  # A command run as root inside the distro; its output is UTF-8.
  $out = & wsl.exe -d $Distro -u root -- bash -c $script 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) { throw "in ${Distro}: $script failed ($LASTEXITCODE): $out" }
  return $out
}

Step 'Windows'
$os = Get-CimInstance Win32_OperatingSystem
$build = [int]$os.BuildNumber
Say "$($os.Caption), build $build"
if ($build -lt 19041) { throw 'WSL2 needs Windows 10 version 2004 (build 19041) or later, or Windows Server 2022 or later.' }
$isServer = $os.ProductType -ne 1
$mirroredOk = (-not $isServer -and $build -ge 22621) -or ($isServer -and $build -ge 26100)
if ($Networking -eq 'auto') { $Networking = $(if ($mirroredOk) { 'mirrored' } else { 'nat' }) }
if ($Networking -eq 'mirrored' -and -not $mirroredOk) { throw 'Mirrored networking needs Windows 11 22H2 or later (or Windows Server 2025); use -Networking nat.' }
Say "networking: $Networking"

Step 'WSL2'
& wsl.exe --status *> $null
if ($LASTEXITCODE -ne 0) {
  Say 'installing WSL (no distribution yet)'
  & wsl.exe --install --no-distribution
  Write-Host "`nWSL is installed. Restart Windows, then run this script again."
  exit 0
}
& wsl.exe --update *> $null
& wsl.exe --set-default-version 2 *> $null
Say ((Wsl @('--version')) -split "`n" | Select-Object -First 1)

Step "the distro $Distro"
$have = (Wsl @('--list', '--quiet')) -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -eq $Distro }
if (-not $have) {
  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  $base = 'https://cloud-images.ubuntu.com/wsl/releases/24.04/current'
  $file = 'ubuntu-noble-wsl-amd64-24.04lts.rootfs.tar.gz'
  $tar = Join-Path $InstallDir $file
  $sums = (Invoke-WebRequest -UseBasicParsing "$base/SHA256SUMS").Content
  $want = ($sums -split "`n" | Where-Object { $_ -match [regex]::Escape($file) } | ForEach-Object { ($_ -split '\s+')[0] }) | Select-Object -First 1
  if (-not $want) { throw "SHA256SUMS at $base names no $file" }
  if (-not (Test-Path $tar) -or (Get-FileHash -Algorithm SHA256 $tar).Hash.ToLower() -ne $want) {
    Say "downloading $file"
    Invoke-WebRequest -UseBasicParsing "$base/$file" -OutFile $tar
  }
  $got = (Get-FileHash -Algorithm SHA256 $tar).Hash.ToLower()
  if ($got -ne $want) { throw "$file has SHA-256 $got, not the published $want" }
  Wsl @('--import', $Distro, (Join-Path $InstallDir 'distro'), $tar, '--version', '2') | Out-Null
  Remove-Item $tar
  Say "imported into $InstallDir\distro"
}
$conf = InDistro 'cat /etc/wsl.conf 2>/dev/null || true'
if ($conf -notmatch 'systemd\s*=\s*true') {
  InDistro "printf '[boot]\nsystemd=true\n\n[user]\ndefault=root\n' > /etc/wsl.conf" | Out-Null
  Wsl @('--terminate', $Distro) | Out-Null
  Say 'systemd on (the distro restarted)'
}
$pid1 = (InDistro 'ps -p 1 -o comm=').Trim()
if ($pid1 -ne 'systemd') { throw "PID 1 in $Distro is $pid1, not systemd: check /etc/wsl.conf and run wsl --shutdown" }
Say (InDistro '. /etc/os-release; echo $PRETTY_NAME').Trim()

Step '.wslconfig'
$cfgPath = Join-Path $env:UserProfile '.wslconfig'
$cfg = if (Test-Path $cfgPath) { Get-Content -Raw $cfgPath } else { '' }
$want = @{ 'vmIdleTimeout' = '-1' }
if ($Networking -eq 'mirrored') { $want['networkingMode'] = 'mirrored'; $want['firewall'] = 'true' }
$lines = [System.Collections.Generic.List[string]]::new()
if ($cfg) { $lines.AddRange([string[]]($cfg -split "`r?`n")) }
if (-not ($lines -match '^\s*\[wsl2\]\s*$')) { $lines.Add('[wsl2]') }
$changed = $false
foreach ($k in $want.Keys) {
  $i = 0; $found = $false
  for (; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match "^\s*$k\s*=") { $found = $true; if ($lines[$i] -ne "$k=$($want[$k])") { $lines[$i] = "$k=$($want[$k])"; $changed = $true }; break }
  }
  if (-not $found) {
    $at = [array]::IndexOf($lines.ToArray(), ($lines | Where-Object { $_ -match '^\s*\[wsl2\]\s*$' } | Select-Object -First 1))
    $lines.Insert($at + 1, "$k=$($want[$k])"); $changed = $true
  }
}
if ($changed) {
  Set-Content -Path $cfgPath -Value ($lines -join "`r`n") -Encoding ascii
  Wsl @('--shutdown') | Out-Null
  Say "wrote $cfgPath (WSL restarted)"
} else { Say 'as wanted already' }

Step 'the ports'
foreach ($p in $Ports) {
  $name = "$Distro inbound TCP $p"
  if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $name -Direction Inbound -Protocol TCP -LocalPort $p -Action Allow | Out-Null
  }
  if ($Networking -eq 'mirrored') {
    $hv = "$Distro Hyper-V inbound TCP $p"
    if (-not (Get-NetFirewallHyperVRule -Name $hv -ErrorAction SilentlyContinue)) {
      # The WSL VM's creator id, the same on every machine.
      New-NetFirewallHyperVRule -Name $hv -DisplayName $hv -Direction Inbound -VMCreatorId '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -Protocol TCP -LocalPorts $p | Out-Null
    }
  }
}
Say "inbound TCP open: $($Ports -join ', ')"

Step 'start at boot'
$starter = Join-Path $InstallDir 'start-bundle.ps1'
@"
# Written by setup-wsl.ps1: starts the $Distro distro, whose systemd starts the
# bundle, and keeps it running. In NAT mode it first points the port proxy at
# the distro's current address.
`$ErrorActionPreference = 'Stop'
`$nat = '$Networking' -eq 'nat'
`$ports = @($($Ports -join ', '))
& wsl.exe -d $Distro -u root -- true
if (`$nat) {
  `$ip = ((& wsl.exe -d $Distro -u root -- hostname -I) -split '\s+' | Where-Object { `$_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1)
  foreach (`$p in `$ports) {
    & netsh.exe interface portproxy delete v4tov4 listenport=`$p listenaddress=0.0.0.0 | Out-Null
    & netsh.exe interface portproxy add v4tov4 listenport=`$p listenaddress=0.0.0.0 connectport=`$p connectaddress=`$ip | Out-Null
  }
}
& wsl.exe -d $Distro -u root --exec /bin/sleep infinity
"@ | Set-Content -Path $starter -Encoding ascii
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$starter`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType S4U -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $Distro -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $Distro
Say "the scheduled task $Distro runs $starter at every start, and runs now"

Step 'next: the bundle, inside the distro'
Write-Host @"
  1. The installer and its settings file (it stops after writing the file):
       wsl -d $Distro -u root -- bash -c "apt-get update && apt-get install -y git && git clone https://github.com/ConcatenaLabs/arca /opt/arca-src && /opt/arca-src/contrib/operator-bundle/install.sh"
  2. Fill in /etc/arca-bundle/bundle.env (ARCA_ASSETS, DOMAIN, CONTACT_NAME):
       wsl -d $Distro -u root -- nano /etc/arca-bundle/bundle.env
  3. Install and start everything (an hour or more the first time: it builds):
       wsl -d $Distro -u root -- /opt/arca-src/contrib/operator-bundle/install.sh
"@
