<#
.SYNOPSIS
    Collect evidence for scitt-verifier's amd-snp-device adapter.

.DESCRIPTION
    Runs on the host of a confidential container. It chooses a fresh nonce,
    asks the guest for an SEV-SNP report bound to that nonce, and fetches the
    report's VCEK and AMD's certificate chain from AMD's Key Distribution
    Service (KDS). The output directory is what

        scitt-verifier verify ... --binding-mode saved-evidence `
            --adapter amd-snp-device --evidence <OutDir>

    expects: report.bin, vcek.der, cert_chain.pem and nonce.hex.

    This script verifies nothing. It only gathers bytes; every one of them is
    authenticated by scitt-verifier, which pins AMD's root itself. Choosing the
    nonce here, immediately before the report is requested, is what makes the
    report fresh, so do not reuse an evidence directory for a later run.

    Works in Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER ContainerId
    The confidential container to request the report from, as crictl knows it.

.PARAMETER OutDir
    Where to write the evidence. Created if absent; existing evidence files in
    it are replaced.

.PARAMETER Crictl
    The crictl executable. Defaults to crictl on PATH.

.PARAMETER ReportCommand
    The command inside the guest that prints a report as hex, given a nonce.

.PARAMETER KdsCache
    Where KDS responses are cached. KDS rate-limits aggressively, and a VCEK
    only changes when the chip's firmware does, so cached certificates are
    reused. To run without network access, populate this directory first.

.PARAMETER Offline
    Never contact KDS; fail if a certificate is not already in the cache.

.EXAMPLE
    . .\common.ps1
    .\collect-snp-evidence.ps1 -ContainerId $id -OutDir C:\evidence\run1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ContainerId,
    [Parameter(Mandatory = $true)][string]$OutDir,
    [string]$Crictl = 'crictl',
    [string]$ReportCommand = 'get-snp-report',
    [string]$KdsCache = (Join-Path $env:LOCALAPPDATA 'scitt-verifier\kds-cache'),
    [switch]$Offline
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

function ConvertTo-Hex([byte[]]$Bytes) {
    -join ($Bytes | ForEach-Object { $_.ToString('x2') })
}

function ConvertFrom-Hex([string]$Text) {
    if ($Text.Length % 2 -ne 0 -or $Text -notmatch '^[0-9a-fA-F]*$') {
        throw "not hex: $($Text.Substring(0, [Math]::Min(40, $Text.Length)))..."
    }
    $bytes = New-Object byte[] ($Text.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Text.Substring($i * 2, 2), 16)
    }
    , $bytes
}

function Get-Kds([string]$Url, [string]$CachePath) {
    if (Test-Path -LiteralPath $CachePath) {
        Write-Host "  cached  $Url"
        return
    }
    if ($Offline) {
        throw "not in the KDS cache and -Offline was given: $CachePath ($Url)"
    }
    $dir = Split-Path -Parent $CachePath
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $partial = "$CachePath.partial"
    $delay = 5
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        try {
            Invoke-WebRequest -Uri $Url -OutFile $partial -UseBasicParsing
            Move-Item -LiteralPath $partial -Destination $CachePath -Force
            Write-Host "  fetched $Url"
            return
        }
        catch {
            $status = $null
            $response = $_.Exception.PSObject.Properties['Response']
            if ($response -and $response.Value) { $status = [int]$response.Value.StatusCode }
            Remove-Item -LiteralPath $partial -ErrorAction SilentlyContinue
            # Retry rate limiting, server errors and network failures; anything
            # else (a 404 for an unknown chip, say) will not improve.
            if ($status -and $status -ne 429 -and $status -lt 500) { throw "KDS request failed ($status): $Url`n$_" }
            Write-Host "  KDS request failed ($status); retrying in $delay s"
            Start-Sleep -Seconds $delay
            $delay = [Math]::Min($delay * 2, 60)
        }
    }
    throw "KDS kept refusing $Url; try again later or populate $CachePath"
}

# KDS requires TLS 1.2, which Windows PowerShell 5.1 does not enable by default.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path -LiteralPath $OutDir).Path
foreach ($name in 'report.bin', 'vcek.der', 'cert_chain.pem', 'nonce.hex') {
    Remove-Item -LiteralPath (Join-Path $OutDir $name) -ErrorAction SilentlyContinue
}

# 1. A fresh nonce. 32 random bytes from the system CSPRNG.
$nonceBytes = New-Object byte[] 32
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($nonceBytes)
$rng.Dispose()
$nonce = ConvertTo-Hex $nonceBytes
Write-Host "Nonce   $nonce"

# 2. The report, requested inside the guest with that nonce as REPORT_DATA.
Write-Host "Report  requesting from container $ContainerId..."
$output = & $Crictl exec $ContainerId $ReportCommand $nonce
if ($LASTEXITCODE -ne 0) { throw "$Crictl exec $ReportCommand failed with exit code $LASTEXITCODE" }
$hex = (($output | Out-String) -replace '\s', '')
$report = ConvertFrom-Hex $hex
if ($report.Length -lt 0x2A0) { throw "the report is $($report.Length) bytes; an SNP report is 1184" }

$version = [BitConverter]::ToUInt32($report, 0)
$tcb = $report[0x180..0x187]
$family = $report[0x188]
$model = $report[0x189]
$chipId = $report[0x1A0..0x1DF]

if ($version -lt 3) {
    throw "report version $version does not record the CPU family; pass a version 3 or later report"
}
if ($family -eq 0x1A) { $product = 'Turin' }
elseif ($family -eq 0x19 -and $model -lt 0x10) { $product = 'Milan' }
elseif ($family -eq 0x19) { $product = 'Genoa' }
else { throw ('unrecognised CPU family 0x{0:x2} model 0x{1:x2}' -f $family, $model) }

# The VCEK is issued for the chip and the firmware it reports, and KDS names
# both in the URL. Turin's hardware ID is 8 bytes; earlier parts use all 64.
if ($product -eq 'Turin') {
    $hwid = ConvertTo-Hex $chipId[0..7]
    $query = 'fmcSPL={0}&blSPL={1}&teeSPL={2}&snpSPL={3}&ucodeSPL={4}' -f $tcb[0], $tcb[1], $tcb[2], $tcb[3], $tcb[7]
}
else {
    $hwid = ConvertTo-Hex $chipId
    $query = 'blSPL={0}&teeSPL={1}&snpSPL={2}&ucodeSPL={3}' -f $tcb[0], $tcb[1], $tcb[6], $tcb[7]
}
Write-Host ("Report  version {0}, {1}, chip {2}, reported TCB {3}" -f $version, $product, $hwid, (ConvertTo-Hex $tcb))

[IO.File]::WriteAllBytes((Join-Path $OutDir 'report.bin'), $report)
[IO.File]::WriteAllText((Join-Path $OutDir 'nonce.hex'), $nonce, [Text.Encoding]::ASCII)

# 3. The VCEK and AMD's chain from KDS, through the cache.
$kds = "https://kdsintf.amd.com/vcek/v1/$product"
$vcekCache = Join-Path $KdsCache "$product\$hwid\$($query -replace '[&=]', '_').der"
$chainCache = Join-Path $KdsCache "$product\cert_chain.pem"
Get-Kds "$kds/${hwid}?$query" $vcekCache
Get-Kds "$kds/cert_chain" $chainCache
Copy-Item -LiteralPath $vcekCache -Destination (Join-Path $OutDir 'vcek.der') -Force
Copy-Item -LiteralPath $chainCache -Destination (Join-Path $OutDir 'cert_chain.pem') -Force

Write-Host ""
Write-Host "Evidence written to $OutDir"
Get-ChildItem -LiteralPath $OutDir | Format-Table Name, Length -AutoSize | Out-String | Write-Host
Write-Host "Next:"
Write-Host "  scitt-verifier verify --statement <HBOM.cose> --scitt-keys <KEYS.cbor> --policy <POLICY.json> ``"
Write-Host "      --binding-mode saved-evidence --adapter amd-snp-device --evidence `"$OutDir`""
