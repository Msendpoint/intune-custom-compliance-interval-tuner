### FILE: scripts/Intune-CustomComplianceInterval-AuditPatch.ps1
<#
.SYNOPSIS
Audits (and optionally patches) Intune custom compliance policy evaluation intervals using Microsoft Graph.

.DESCRIPTION
This script connects to Microsoft Graph, reads device compliance policies, filters for Windows and/or macOS custom compliance policies, exports the current policy JSON for auditing, and (optionally) patches the evaluation interval when the interval parameter is provided.

It implements retry logic for transient Graph failures (HTTP 429/5xx) and supports schema-conscious behavior by reading policy objects from Graph before attempting to update.

.EXAMPLE
# Discover and export current compliance policies (read-only)
.
Intune-CustomComplianceInterval-AuditPatch.ps1 -Mode Discover -Platform All -ExportPath .\audit

.EXAMPLE
# Patch a specific policy to a 30-minute evaluation interval
.
Intune-CustomComplianceInterval-AuditPatch.ps1 -Mode Patch -PolicyName "My Custom Compliance Policy" -Platform windows10CompliancePolicy -Interval "30m" -ExportPath .\audit

.NOTES
Author:      Souhaiel Morhag
Company:     MSEndpoint.com
Blog:        https://msendpoint.com
Academy:     https://app.msendpoint.com/academy
LinkedIn:    https://linkedin.com/in/souhaiel-morhag
GitHub:      https://github.com/Msendpoint
License:     MIT
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param (
    [Parameter(Mandatory = $false)]
    [ValidateSet('INFO', 'WARN', 'ERROR', 'OK')]
    [string]$LogDefaultLevel = 'INFO',

    [Parameter(Mandatory = $false)]
    [ValidateSet('Discover', 'Patch')]
    [string]$Mode = 'Discover',

    [Parameter(Mandatory = $false)]
    [ValidateSet('windows10CompliancePolicy', 'macOSCompliancePolicy', 'All')]
    [string]$Platform = 'All',

    [Parameter(Mandatory = $false)]
    [string]$PolicyName,

    [Parameter(Mandatory = $false)]
    [ValidateSet('15m', '30m', '1h', '2h', '4h', '8h')]
    [string]$Interval,

    # Optional: if you already know the exact Graph property path for your tenant,
    # you can provide it to avoid guessing.
    # Example: -IntervalPropertyPath 'windowsCustomCompliance.evaluationInterval'
    [Parameter(Mandatory = $false)]
    [string]$IntervalPropertyPath,

    [Parameter(Mandatory = $false)]
    [string]$ExportPath = '.\Intune-CustomComplianceInterval-Audit',

    [Parameter(Mandatory = $false)]
    [int]$MaxRetryCount = 6
)

$ErrorActionPreference = 'Stop'

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'OK')]
        [string]$Level = $LogDefaultLevel
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    switch ($Level) {
        'INFO'  { Write-Host "[$timestamp] [INFO ] $Message" -ForegroundColor Cyan }
        'WARN'  { Write-Host "[$timestamp] [WARN ] $Message" -ForegroundColor Yellow }
        'ERROR' { Write-Host "[$timestamp] [ERROR] $Message" -ForegroundColor Red }
        'OK'    { Write-Host "[$timestamp] [ OK  ] $Message" -ForegroundColor Green }
    }
}

function Ensure-GraphConnection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Scopes
    )

    try {
        $ctx = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $ctx) {
            Write-Log -Message 'Connecting to Microsoft Graph...' -Level 'INFO'
            Connect-MgGraph -Scopes $Scopes -NoWelcome | Out-Null
        } else {
            Write-Log -Message "Using existing Microsoft Graph context for tenant $($ctx.TenantId)." -Level 'OK'
        }
    }
    catch {
        Write-Log -Level 'ERROR' -Message "Failed to connect to Microsoft Graph. $($_.Exception.Message)"
        throw
    }
}

function Invoke-GraphRequestWithRetry {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'PATCH')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [object]$Body
    )

    $attempt = 0
    do {
        try {
            $attempt++

            if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
                return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body ($Body | ConvertTo-Json -Depth 30)
            }

            return Invoke-MgGraphRequest -Method $Method -Uri $Uri
        }
        catch {
            $statusCode = $null
            $retryAfter = 0

            if ($_.Exception.Response) {
                try {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                    if ($_.Exception.Response.Headers -and $_.Exception.Response.Headers.RetryAfter) {
                        $retryAfter = [int]$_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds
                    }
                }
                catch {
                    # Best-effort parsing (header formats can vary)
                }
            }

            $isTransient = ($statusCode -eq 429) -or ($statusCode -ge 500 -and $statusCode -lt 600)
            if ($isTransient) {
                if ($attempt -ge $MaxRetryCount) {
                    Write-Log -Level 'ERROR' -Message "Graph transient error persisted after $MaxRetryCount attempts. HTTP: $statusCode."
                    throw
                }

                if ($retryAfter -le 0) {
                    $retryAfter = [Math]::Min((2 * $attempt), 30)
                }

                Write-Log -Level 'WARN' -Message "Graph returned HTTP $statusCode for $Method $Uri. Retrying in $retryAfter second(s). Attempt $attempt of $MaxRetryCount."
                Start-Sleep -Seconds $retryAfter
            }
            else {
                throw
            }
        }
    } while ($attempt -lt $MaxRetryCount)
}

function Convert-IntervalToPayloadValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('15m', '30m', '1h', '2h', '4h', '8h')]
        [string]$Interval
    )

    switch ($Interval) {
        '15m' { return '15Minutes' }
        '30m' { return '30Minutes' }
        '1h'  { return '1Hour' }
        '2h'  { return '2Hours' }
        '4h'  { return '4Hours' }
        '8h'  { return '8Hours' }
        default { throw "Unsupported interval value: $Interval" }
    }
}

function Set-NestedValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Target,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [object]$Value
    )

    $parts = $Path -split '\.'
    $current = $Target

    for ($i = 0; $i -lt ($parts.Count - 1); $i++) {
        $part = $parts[$i]
        if (-not $current.ContainsKey($part) -or $null -eq $current[$part]) {
            $current[$part] = @{}
        }
        $current = $current[$part]
    }

    $current[$parts[-1]] = $Value
    return $Target
}

function Get-PolicyTargets {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Policies,

        [Parameter(Mandatory = $true)]
        [ValidateSet('windows10CompliancePolicy', 'macOSCompliancePolicy', 'All')]
        [string]$Platform,

        [Parameter(Mandatory = $false)]
        [string]$PolicyName
    )

    $filtered = foreach ($policy in $Policies) {
        $odataType = $policy.'@odata.type'
        $isWindows = $odataType -match 'windows'
        $isMac = $odataType -match 'macOS|mac'

        if ($Platform -eq 'All' -and ($isWindows -or $isMac)) { $policy }
        elseif ($Platform -eq 'windows10CompliancePolicy' -and $isWindows) { $policy }
        elseif ($Platform -eq 'macOSCompliancePolicy' -and $isMac) { $policy }
    }

    if ($PolicyName) {
        $filtered = $filtered | Where-Object { $_.displayName -eq $PolicyName }
    }

    return $filtered
}

try {
    if (-not (Test-Path -Path $ExportPath)) {
        New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
    }

    $requiredScopes = if ($Mode -eq 'Patch') {
        @('DeviceManagementConfiguration.ReadWrite.All')
    }
    else {
        @('DeviceManagementConfiguration.Read.All')
    }

    Ensure-GraphConnection -Scopes $requiredScopes

    $listUri = 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies'
    Write-Log -Message 'Retrieving compliance policies from Graph...' -Level 'INFO'
    $response = Invoke-GraphRequestWithRetry -Method 'GET' -Uri $listUri
    $policies = @($response.value)

    if (-not $policies -or $policies.Count -eq 0) {
        Write-Log -Level 'WARN' -Message 'No compliance policies returned from Graph.'
        return
    }

    $targetPolicies = Get-PolicyTargets -Policies $policies -Platform $Platform -PolicyName $PolicyName

    if (-not $targetPolicies -or $targetPolicies.Count -eq 0) {
        Write-Log -Level 'WARN' -Message 'No matching Windows/macOS compliance policies found.'
        return
    }

    if ($Mode -eq 'Patch' -and -not $Interval) {
        throw 'Mode=Patch requires -Interval. (Example: -Interval "30m")'
    }

    $payloadValue = if ($Mode -eq 'Patch') { Convert-IntervalToPayloadValue -Interval $Interval } else { $null }

    foreach ($policy in $targetPolicies) {
        $policyId = $policy.id
        $detailUri = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/$policyId"

        Write-Log -Message "Processing policy: $($policy.displayName) ($policyId)" -Level 'INFO'

        # Read full object for audit and (optional) patch payload creation
        $detail = Invoke-GraphRequestWithRetry -Method 'GET' -Uri $detailUri

        $safeName = ($detail.displayName ?? $policy.displayName).Replace(' ', '_')
        $jsonBefore = Join-Path -Path $ExportPath -ChildPath ("{0}-{1}