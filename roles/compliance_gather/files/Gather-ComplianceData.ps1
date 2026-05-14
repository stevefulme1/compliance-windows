<#
.SYNOPSIS
    Collect registry values, security policies, audit policies, and service
    states in a single WinRM round-trip for compliance pre-assessment.
.DESCRIPTION
    Returns a JSON object with sections: registry, secpol, auditpol, services.
    Designed to be invoked by the compliance_gather Ansible role.
#>
param(
    [string[]]$RegistryPaths = @(),
    [bool]$IncludeSecurityPolicies = $true,
    [bool]$IncludeAuditPolicies = $true,
    [bool]$IncludeServices = $true
)

$result = @{}

# Registry values
if ($RegistryPaths.Count -gt 0) {
    $regData = @{}
    foreach ($path in $RegistryPaths) {
        try {
            $item = Get-ItemProperty -Path $path -ErrorAction Stop
            $regData[$path] = @{}
            foreach ($prop in $item.PSObject.Properties) {
                if ($prop.Name -notmatch '^PS') {
                    $regData[$path][$prop.Name] = $prop.Value
                }
            }
        } catch {
            $regData[$path] = @{ "_error" = $_.Exception.Message }
        }
    }
    $result["registry"] = $regData
}

# Security policies via secedit
if ($IncludeSecurityPolicies) {
    $tempFile = [System.IO.Path]::GetTempFileName()
    try {
        $null = secedit /export /cfg $tempFile /quiet
        $content = Get-Content -Path $tempFile -Raw
        $secpol = @{}
        $currentSection = ""
        foreach ($line in $content -split "`n") {
            $line = $line.Trim()
            if ($line -match '^\[(.+)\]$') {
                $currentSection = $Matches[1]
                $secpol[$currentSection] = @{}
            } elseif ($line -match '^(.+?)\s*=\s*(.+)$' -and $currentSection) {
                $secpol[$currentSection][$Matches[1].Trim()] = $Matches[2].Trim()
            }
        }
        $result["secpol"] = $secpol
    } finally {
        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
    }
}

# Audit policies
if ($IncludeAuditPolicies) {
    try {
        $auditCsv = auditpol /get /category:* /r | ConvertFrom-Csv
        $auditData = @{}
        foreach ($entry in $auditCsv) {
            $auditData[$entry.Subcategory] = @{
                "guid"    = $entry.'Subcategory GUID'
                "setting" = $entry.'Inclusion Setting'
            }
        }
        $result["auditpol"] = $auditData
    } catch {
        $result["auditpol"] = @{ "_error" = $_.Exception.Message }
    }
}

# Services
if ($IncludeServices) {
    $services = Get-Service | Select-Object Name, DisplayName, Status, StartType |
        ForEach-Object {
            @{
                "name"       = $_.Name
                "display"    = $_.DisplayName
                "status"     = $_.Status.ToString()
                "start_type" = $_.StartType.ToString()
            }
        }
    $result["services"] = $services
}

$result | ConvertTo-Json -Depth 10 -Compress
