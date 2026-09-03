<#
.SYNOPSIS
    Push static User-IP mappings from mappings.xml to a PAN NGFW via XML API.

.DESCRIPTION
    Reads PAN_HOSTNAME and PAN_API_KEY from .env, then POSTs mappings.xml as
    type=user-id. No commit is required; the mapping is applied immediately.
    Use -Clear to remove mappings created via the XML API only.

.EXAMPLE
    .\push_user_mapping.ps1
    .\push_user_mapping.ps1 -DryRun
    .\push_user_mapping.ps1 -File mappings.xml
    .\push_user_mapping.ps1 -Clear
    .\push_user_mapping.ps1 -ClearIp 192.0.2.10
#>
[CmdletBinding()]
param(
    [string]$File,
    [switch]$DryRun,
    [switch]$Clear,
    [string]$ClearIp
)

$ErrorActionPreference = "Stop"
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $File) {
    $File = Join-Path $ScriptDir "mappings.xml"
}

function Import-DotEnv {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw ".env file not found at $Path. Copy .env.example to .env and fill in values."
    }

    Get-Content -LiteralPath $Path | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#")) {
            return
        }
        $parts = $line.Split("=", 2)
        if ($parts.Count -ne 2) {
            return
        }
        $name = $parts[0].Trim()
        $value = $parts[1].Trim().Trim("'").Trim('"')
        Set-Item -Path "Env:$name" -Value $value
    }
}

function Get-PanConfig {
    $hostname = ($env:PAN_HOSTNAME).Trim()
    $apiKey = ($env:PAN_API_KEY).Trim()
    $vsys = if ($env:PAN_VSYS) { $env:PAN_VSYS.Trim() } else { "vsys1" }
    if (-not $vsys) { $vsys = "vsys1" }
    $verifySsl = $env:PAN_VERIFY_SSL -match "^(1|true|yes|on)$"

    if (-not $hostname -or -not $apiKey) {
        throw "Missing PAN_HOSTNAME or PAN_API_KEY in .env."
    }
    if ($apiKey -in @("your-xml-api-key-here", "changeme")) {
        throw "PAN_API_KEY in .env is still the placeholder. Replace it with the firewall API key."
    }

    return [pscustomobject]@{
        Hostname  = $hostname.TrimEnd("/")
        ApiKey    = $apiKey
        Vsys      = $vsys
        VerifySsl = $verifySsl
    }
}

function Format-Mappings {
    param([string]$UidXml)

    $doc = [xml]$UidXml
    $payload = $doc.'uid-message'.payload
    if (-not $payload) {
        return @()
    }

    $lines = @()
    foreach ($action in @("login", "logout")) {
        $section = $payload.$action
        if (-not $section) {
            continue
        }
        if ($section.all) {
            $lines += "  $action  all XML API entries"
            continue
        }
        foreach ($entry in @($section.entry)) {
            $name = if ($entry.name) { $entry.name } else { "(no user)" }
            $ip = [string]$entry.ip
            $extra = if ($entry.timeout) { "  timeout=$($entry.timeout)" } else { "" }
            $lines += "  $action  $name  $ip$extra"
        }
    }
    return $lines
}

function Write-Mappings {
    param([string]$UidXml)

    $lines = Format-Mappings -UidXml $UidXml
    if (-not $lines) {
        return
    }
    Write-Host "Mappings:"
    foreach ($line in $lines) {
        Write-Host $line
    }
}

function Disable-UntrustedSsl {
    if (-not ("TrustAllCertsPolicy" -as [type])) {
        Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
    }
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}

if ($Clear -and $ClearIp) {
    throw "-Clear and -ClearIp are mutually exclusive."
}

if ($Clear) {
    $uidXml = @"
<uid-message>
  <version>1.0</version>
  <type>update</type>
  <payload>
    <logout>
      <all/>
    </logout>
  </payload>
</uid-message>
"@.Trim()
} elseif ($ClearIp) {
    $uidXml = @"
<uid-message>
  <version>1.0</version>
  <type>update</type>
  <payload>
    <logout>
      <entry ip="$ClearIp"/>
    </logout>
  </payload>
</uid-message>
"@.Trim()
} else {
    if (-not (Test-Path -LiteralPath $File)) {
        throw "Mappings file not found: $File"
    }

    $uidXml = (Get-Content -LiteralPath $File -Raw).Trim()
    if ($uidXml -notmatch "<uid-message" -or ($uidXml -notmatch "<login" -and $uidXml -notmatch "<logout")) {
        throw "$File must contain a uid-message with login and/or logout entries."
    }
}

if ($DryRun) {
    Write-Output $uidXml
    exit 0
}

Import-DotEnv -Path (Join-Path $ScriptDir ".env")
$config = Get-PanConfig

if ($Clear) {
    Write-Host "Clearing all XML API User-ID mappings on $($config.Hostname) ($($config.Vsys))..."
    $accepted = "Firewall cleared all XML API User-ID mappings."
} elseif ($ClearIp) {
    Write-Host "Clearing XML API User-ID mapping for $ClearIp on $($config.Hostname) ($($config.Vsys))..."
    $accepted = "Firewall cleared XML API User-ID mapping for $ClearIp."
} else {
    Write-Host "Pushing User-ID mapping from $(Split-Path $File -Leaf) to $($config.Hostname) ($($config.Vsys))..."
    $accepted = "Firewall accepted the User-ID mapping."
}

if (-not $config.VerifySsl) {
    Disable-UntrustedSsl
}

$uri = "https://$($config.Hostname)/api/"
$body = @{
    type = "user-id"
    key  = $config.ApiKey
    vsys = $config.Vsys
    cmd  = $uidXml
}

try {
    $response = Invoke-WebRequest -Uri $uri -Method Post -Body $body -UseBasicParsing
} catch {
    throw "XML API request failed: $($_.Exception.Message)"
}

$text = $response.Content.Trim()
if ($text -notmatch 'status="success"' -and $text -notmatch "status='success'") {
    throw "XML API rejected the mapping:`n$text"
}

Write-Host $accepted
Write-Mappings -UidXml $uidXml
Write-Output $text
