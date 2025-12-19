<#
.SYNOPSIS
    Manages Cloudflare Browser-Based RDP Access Applications synced with Active Directory group membership.

.DESCRIPTION
    This script queries a specified Active Directory group to retrieve user accounts with their email addresses
    and a custom attribute containing RDP hostnames. It then creates/manages Cloudflare Access applications
    for Browser-Based RDP access, including:
    - Adding /32 CIDR entries to Cloudflare Tunnel
    - Creating Access Targets
    - Creating Self-Hosted Access Applications with Browser RDP rendering
    - Creating Access Policies with email-based rules
    
    The script supports incremental sync - only creating apps for new users and prompting for deletion
    of apps for removed users.

.PARAMETER ADGroup
    The name or Distinguished Name of the Active Directory group to query.
    Can also be set via environment variable: CF_BROWSER_RDP_AD_GROUP

.PARAMETER ADHostnameAttribute
    The AD attribute containing the RDP hostname for each user.
    Can also be set via environment variable: CF_BROWSER_RDP_AD_HOSTNAME_ATTR

.PARAMETER CloudflareAccountId
    The Cloudflare Account ID.
    Can also be set via environment variable: CF_ACCOUNT_ID

.PARAMETER CloudflareApiToken
    The Cloudflare API Token with required permissions.
    Can also be set via environment variable: CF_API_TOKEN

.PARAMETER CloudflareTunnelId
    The Cloudflare Tunnel ID for adding CIDR routes.
    Can also be set via environment variable: CF_TUNNEL_ID

.PARAMETER CloudflareZoneId
    The Cloudflare Zone ID where DNS records will be created.
    Can also be set via environment variable: CF_ZONE_ID

.PARAMETER IdentityProviderId
    The Cloudflare Identity Provider ID to use for policies.
    Can also be set via environment variable: CF_IDP_ID

.PARAMETER LogPath
    Path for log file output. Defaults to script directory.
    Can also be set via environment variable: CF_BROWSER_RDP_LOG_PATH

.PARAMETER DryRun
    If specified, shows what would be done without making changes.

.EXAMPLE
    .\Manage-CloudflareBrowserRDP.ps1 -ADGroup "RDP-Users" -ADHostnameAttribute "extensionAttribute1"

.EXAMPLE
    .\Manage-CloudflareBrowserRDP.ps1 -DryRun

.NOTES
    Requires:
    - PowerShell 5.1 or higher
    - Active Directory PowerShell module
    - Network access to Cloudflare API and AD
    
    See README-API-PERMISSIONS.md for detailed API token requirements.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ADGroup,

    [Parameter()]
    [string]$ADHostnameAttribute,

    [Parameter()]
    [string]$CloudflareAccountId,

    [Parameter()]
    [string]$CloudflareApiToken,

    [Parameter()]
    [string]$CloudflareTunnelId,

    [Parameter()]
    [string]$CloudflareZoneId,

    [Parameter()]
    [string]$IdentityProviderId,

    [Parameter()]
    [string]$LogPath,

    [Parameter()]
    [switch]$DryRun
)

#region Configuration and Initialization

$ErrorActionPreference = "Stop"
$Script:LogFile = $null

# Script metadata
$ScriptVersion = "1.0.0"
$ScriptName = "Manage-CloudflareBrowserRDP"

#endregion

#region Logging Functions

function Initialize-Logging {
    param([string]$Path)
    
    if ([string]::IsNullOrEmpty($Path)) {
        $Path = $PSScriptRoot
    }
    
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $Script:LogFile = Join-Path $Path "$ScriptName`_$timestamp.log"
    
    Write-Log ("=" * 80) -NoTimestamp
    Write-Log "$ScriptName v$ScriptVersion started" -Level "INFO"
    Write-Log "Log file: $Script:LogFile" -Level "INFO"
    Write-Log ("=" * 80) -NoTimestamp
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG", "SUCCESS")]
        [string]$Level = "INFO",
        
        [Parameter()]
        [switch]$NoTimestamp
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    if ($NoTimestamp) {
        $logMessage = $Message
    } else {
        $logMessage = "[$timestamp] [$Level] $Message"
    }
    
    # Console output with colors
    $color = switch ($Level) {
        "INFO"    { "White" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        "DEBUG"   { "Gray" }
        "SUCCESS" { "Green" }
        default   { "White" }
    }
    
    Write-Host $logMessage -ForegroundColor $color
    
    # File output
    if ($Script:LogFile) {
        Add-Content -Path $Script:LogFile -Value $logMessage
    }
}

#endregion

#region Parameter Resolution Functions

function Get-ParameterValue {
    param(
        [string]$ParamValue,
        [string]$EnvVarName,
        [string]$PromptMessage,
        [switch]$Required,
        [switch]$IsSecret
    )
    
    # Priority 1: Command line parameter
    if (-not [string]::IsNullOrEmpty($ParamValue)) {
        Write-Log "Using command line value for $PromptMessage" -Level "DEBUG"
        return $ParamValue.Trim()
    }
    
    # Priority 2: Environment variable
    $envValue = [Environment]::GetEnvironmentVariable($EnvVarName)
    if (-not [string]::IsNullOrEmpty($envValue)) {
        Write-Log "Using environment variable $EnvVarName for $PromptMessage" -Level "DEBUG"
        return $envValue.Trim()
    }
    
    # Priority 3: Interactive prompt
    if ($Required -or (-not $Required)) {
        if ($IsSecret) {
            $secureValue = Read-Host -Prompt $PromptMessage -AsSecureString
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureValue)
            try {
                $plainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                return $plainText.Trim()
            } finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        } else {
            $value = Read-Host -Prompt $PromptMessage
            return $value.Trim()
        }
    }
    
    if ($Required) {
        throw "Required parameter not provided: $PromptMessage"
    }
    
    return $null
}

function Initialize-Parameters {
    Write-Log "Initializing parameters..." -Level "INFO"
    
    $script:Config = @{
        ADGroup = Get-ParameterValue `
            -ParamValue $ADGroup `
            -EnvVarName "CF_BROWSER_RDP_AD_GROUP" `
            -PromptMessage "Enter Active Directory Group name (e.g., RDP-Users)" `
            -Required
        
        ADHostnameAttribute = Get-ParameterValue `
            -ParamValue $ADHostnameAttribute `
            -EnvVarName "CF_BROWSER_RDP_AD_HOSTNAME_ATTR" `
            -PromptMessage "Enter AD attribute containing RDP hostname (e.g., extensionAttribute1)" `
            -Required
        
        CloudflareAccountId = Get-ParameterValue `
            -ParamValue $CloudflareAccountId `
            -EnvVarName "CF_ACCOUNT_ID" `
            -PromptMessage "Enter Cloudflare Account ID" `
            -Required
        
        CloudflareApiToken = Get-ParameterValue `
            -ParamValue $CloudflareApiToken `
            -EnvVarName "CF_API_TOKEN" `
            -PromptMessage "Enter Cloudflare API Token" `
            -Required `
            -IsSecret
        
        CloudflareTunnelId = $CloudflareTunnelId
        
        CloudflareZoneId = $CloudflareZoneId
        
        IdentityProviderId = $IdentityProviderId
        
        ZoneName = $null
        
        LogPath = if ([string]::IsNullOrEmpty($LogPath)) { 
            [Environment]::GetEnvironmentVariable("CF_BROWSER_RDP_LOG_PATH") 
        } else { 
            $LogPath 
        }
    }
    
    Write-Log "Parameters initialized successfully" -Level "SUCCESS"
    Write-Log "AD Group: $($script:Config.ADGroup)" -Level "DEBUG"
    Write-Log "AD Hostname Attribute: $($script:Config.ADHostnameAttribute)" -Level "DEBUG"
    Write-Log "Cloudflare Account ID: $($script:Config.CloudflareAccountId)" -Level "DEBUG"
}

#endregion

#region Cloudflare API Functions

function Get-CloudflareHeaders {
    return @{
        "Authorization" = "Bearer $($script:Config.CloudflareApiToken)"
        "Content-Type"  = "application/json"
    }
}

function Invoke-CloudflareApi {
    param(
        [Parameter(Mandatory)]
        [string]$Endpoint,
        
        [Parameter()]
        [ValidateSet("GET", "POST", "PUT", "DELETE", "PATCH")]
        [string]$Method = "GET",
        
        [Parameter()]
        [object]$Body,
        
        [Parameter()]
        [switch]$IgnoreErrors
    )
    
    $baseUrl = "https://api.cloudflare.com/client/v4"
    $url = "$baseUrl$Endpoint"
    
    $params = @{
        Uri     = $url
        Method  = $Method
        Headers = Get-CloudflareHeaders
    }
    
    if ($Body) {
        $params.Body = $Body | ConvertTo-Json -Depth 10
    }
    
    try {
        Write-Log "API Call: $Method $Endpoint" -Level "DEBUG"
        $response = Invoke-RestMethod @params
        
        if ($response.success -eq $false -and -not $IgnoreErrors) {
            $errorMsg = ($response.errors | ForEach-Object { $_.message }) -join "; "
            throw "Cloudflare API Error: $errorMsg"
        }
        
        return $response
    }
    catch {
        if (-not $IgnoreErrors) {
            Write-Log "API Error: $($_.Exception.Message)" -Level "ERROR"
            throw
        }
        return $null
    }
}

function Test-CloudflareConnection {
    Write-Log "Testing Cloudflare API connection..." -Level "INFO"
    
    try {
        $result = Invoke-CloudflareApi -Endpoint "/user/tokens/verify"
        if ($result.success) {
            Write-Log "Cloudflare API connection successful" -Level "SUCCESS"
            return $true
        }
    }
    catch {
        Write-Log "Failed to connect to Cloudflare API: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
    
    return $false
}

function Get-CloudflareTunnels {
    Write-Log "Retrieving Cloudflare Tunnels..." -Level "INFO"
    
    $response = Invoke-CloudflareApi -Endpoint "/accounts/$($script:Config.CloudflareAccountId)/cfd_tunnel"
    
    if ($response.result) {
        # Filter to only active tunnels
        $activeTunnels = $response.result | Where-Object { $_.status -eq "healthy" -or $_.status -eq "active" -or $null -eq $_.deleted_at }
        Write-Log "Found $($activeTunnels.Count) tunnel(s)" -Level "INFO"
        return $activeTunnels
    }
    
    return @()
}

function Select-CloudflareTunnel {
    # Check if already specified via parameter
    if (-not [string]::IsNullOrEmpty($script:Config.CloudflareTunnelId)) {
        Write-Log "Using pre-configured Tunnel ID: $($script:Config.CloudflareTunnelId)" -Level "INFO"
        return $script:Config.CloudflareTunnelId
    }
    
    # Check environment variable
    $envTunnelId = [Environment]::GetEnvironmentVariable("CF_TUNNEL_ID")
    if (-not [string]::IsNullOrEmpty($envTunnelId)) {
        $script:Config.CloudflareTunnelId = $envTunnelId
        Write-Log "Using Tunnel ID from environment variable: $envTunnelId" -Level "INFO"
        return $envTunnelId
    }
    
    # Interactive selection
    $tunnels = Get-CloudflareTunnels
    
    if ($tunnels.Count -eq 0) {
        throw "No Cloudflare Tunnels found in this account"
    }
    
    Write-Host "`nAvailable Cloudflare Tunnels:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $tunnels.Count; $i++) {
        $status = if ($tunnels[$i].status) { $tunnels[$i].status } else { "unknown" }
        Write-Host "  [$($i + 1)] $($tunnels[$i].name) (Status: $status, ID: $($tunnels[$i].id))"
    }
    
    do {
        $selection = Read-Host "`nSelect Cloudflare Tunnel (1-$($tunnels.Count))"
        $index = [int]$selection - 1
    } while ($index -lt 0 -or $index -ge $tunnels.Count)
    
    $selectedTunnel = $tunnels[$index]
    $script:Config.CloudflareTunnelId = $selectedTunnel.id
    Write-Log "Selected Tunnel: $($selectedTunnel.name) ($($selectedTunnel.id))" -Level "SUCCESS"
    
    return $selectedTunnel.id
}

function Get-CloudflareIdentityProviders {
    Write-Log "Retrieving Cloudflare Identity Providers..." -Level "INFO"
    
    $response = Invoke-CloudflareApi -Endpoint "/accounts/$($script:Config.CloudflareAccountId)/access/identity_providers"
    
    if ($response.result) {
        Write-Log "Found $($response.result.Count) identity provider(s)" -Level "INFO"
        return $response.result
    }
    
    return @()
}

function Select-IdentityProvider {
    # Check if already specified via parameter
    if (-not [string]::IsNullOrEmpty($script:Config.IdentityProviderId)) {
        Write-Log "Using pre-configured Identity Provider: $($script:Config.IdentityProviderId)" -Level "INFO"
        return $script:Config.IdentityProviderId
    }
    
    # Check environment variable
    $envIdp = [Environment]::GetEnvironmentVariable("CF_IDP_ID")
    if (-not [string]::IsNullOrEmpty($envIdp)) {
        $script:Config.IdentityProviderId = $envIdp
        Write-Log "Using Identity Provider from environment variable: $envIdp" -Level "INFO"
        return $envIdp
    }
    
    # Interactive selection
    $idps = Get-CloudflareIdentityProviders
    
    if ($idps.Count -eq 0) {
        throw "No Identity Providers configured in Cloudflare Access"
    }
    
    Write-Host "`nAvailable Identity Providers:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $idps.Count; $i++) {
        Write-Host "  [$($i + 1)] $($idps[$i].name) (Type: $($idps[$i].type), ID: $($idps[$i].id))"
    }
    
    do {
        $selection = Read-Host "`nSelect Identity Provider (1-$($idps.Count))"
        $index = [int]$selection - 1
    } while ($index -lt 0 -or $index -ge $idps.Count)
    
    $selectedIdp = $idps[$index]
    $script:Config.IdentityProviderId = $selectedIdp.id
    Write-Log "Selected Identity Provider: $($selectedIdp.name) ($($selectedIdp.id))" -Level "SUCCESS"
    
    return $selectedIdp.id
}

function Get-CloudflareZones {
    Write-Log "Retrieving Cloudflare Zones..." -Level "INFO"
    
    $response = Invoke-CloudflareApi -Endpoint "/zones"
    
    if ($response.result) {
        Write-Log "Found $($response.result.Count) zone(s)" -Level "INFO"
        return $response.result
    }
    
    return @()
}

function Select-CloudflareZone {
    # Check if already specified via parameter
    if (-not [string]::IsNullOrEmpty($script:Config.CloudflareZoneId)) {
        Write-Log "Using pre-configured Zone ID: $($script:Config.CloudflareZoneId)" -Level "INFO"
        # Get zone name for the pre-configured zone
        $zones = Get-CloudflareZones
        $zone = $zones | Where-Object { $_.id -eq $script:Config.CloudflareZoneId }
        if ($zone) {
            $script:Config.ZoneName = $zone.name
            Write-Log "Zone Name: $($zone.name)" -Level "DEBUG"
        }
        return $script:Config.CloudflareZoneId
    }
    
    # Check environment variable
    $envZoneId = [Environment]::GetEnvironmentVariable("CF_ZONE_ID")
    if (-not [string]::IsNullOrEmpty($envZoneId)) {
        $script:Config.CloudflareZoneId = $envZoneId
        Write-Log "Using Zone ID from environment variable: $envZoneId" -Level "INFO"
        # Get zone name
        $zones = Get-CloudflareZones
        $zone = $zones | Where-Object { $_.id -eq $envZoneId }
        if ($zone) {
            $script:Config.ZoneName = $zone.name
        }
        return $envZoneId
    }
    
    # Interactive selection
    $zones = Get-CloudflareZones
    
    if ($zones.Count -eq 0) {
        throw "No Cloudflare Zones found accessible by this API token"
    }
    
    Write-Host "`nAvailable Cloudflare Zones:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $zones.Count; $i++) {
        Write-Host "  [$($i + 1)] $($zones[$i].name) (ID: $($zones[$i].id))"
    }
    
    do {
        $selection = Read-Host "`nSelect Cloudflare Zone for DNS records (1-$($zones.Count))"
        $index = [int]$selection - 1
    } while ($index -lt 0 -or $index -ge $zones.Count)
    
    $selectedZone = $zones[$index]
    $script:Config.CloudflareZoneId = $selectedZone.id
    $script:Config.ZoneName = $selectedZone.name
    Write-Log "Selected Zone: $($selectedZone.name) ($($selectedZone.id))" -Level "SUCCESS"
    
    return $selectedZone.id
}

function Get-CloudflareDnsRecords {
    param(
        [Parameter()]
        [string]$Name
    )
    
    $endpoint = "/zones/$($script:Config.CloudflareZoneId)/dns_records"
    if (-not [string]::IsNullOrEmpty($Name)) {
        $endpoint += "?name=$Name"
    }
    
    $response = Invoke-CloudflareApi -Endpoint $endpoint
    
    if ($response.result) {
        return $response.result
    }
    
    return @()
}

function New-CloudflareDnsRecord {
    param(
        [Parameter(Mandatory)]
        [string]$SamAccountName
    )
    
    # Build the DNS hostname: {samaccountname}-rdp.{zonename}
    $dnsName = "$($SamAccountName.ToLower())-rdp.$($script:Config.ZoneName)"
    
    Write-Log "Creating DNS record: $dnsName..." -Level "INFO"
    
    # Check if DNS record already exists
    $existingRecords = Get-CloudflareDnsRecords -Name $dnsName
    if ($existingRecords.Count -gt 0) {
        Write-Log "DNS record $dnsName already exists" -Level "WARN"
        return @{
            name = $dnsName
            id = $existingRecords[0].id
            existing = $true
        }
    }
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would create DNS A record: $dnsName -> 240.0.0.0" -Level "INFO"
        return @{
            name = $dnsName
            id = "dry-run-dns-id"
            existing = $false
        }
    }
    
    # Create A record pointing to 240.0.0.0 (Cloudflare proxy will handle routing)
    $body = @{
        type    = "A"
        name    = $dnsName
        content = "240.0.0.0"
        proxied = $true
        ttl     = 1
    }
    
    $response = Invoke-CloudflareApi -Endpoint "/zones/$($script:Config.CloudflareZoneId)/dns_records" -Method "POST" -Body $body
    
    if ($response.result) {
        Write-Log "Successfully created DNS record: $dnsName -> 240.0.0.0" -Level "SUCCESS"
        return @{
            name = $dnsName
            id = $response.result.id
            existing = $false
        }
    }
    
    throw "Failed to create DNS record: $dnsName"
}

function Remove-CloudflareDnsRecord {
    param(
        [Parameter(Mandatory)]
        [string]$DnsName
    )
    
    Write-Log "Removing DNS record: $DnsName..." -Level "INFO"
    
    # Find the record
    $records = Get-CloudflareDnsRecords -Name $DnsName
    
    if ($records.Count -eq 0) {
        Write-Log "DNS record $DnsName not found - nothing to remove" -Level "WARN"
        return $true
    }
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would remove DNS record: $DnsName" -Level "INFO"
        return $true
    }
    
    $recordId = $records[0].id
    $response = Invoke-CloudflareApi -Endpoint "/zones/$($script:Config.CloudflareZoneId)/dns_records/$recordId" -Method "DELETE"
    
    if ($response.success) {
        Write-Log "Successfully removed DNS record: $DnsName" -Level "SUCCESS"
        return $true
    }
    
    return $false
}

function Get-CloudflareTunnelRoutes {
    Write-Log "Retrieving existing tunnel routes..." -Level "INFO"
    
    $response = Invoke-CloudflareApi -Endpoint "/accounts/$($script:Config.CloudflareAccountId)/teamnet/routes?tunnel_id=$($script:Config.CloudflareTunnelId)"
    
    if ($response.result) {
        return $response.result
    }
    
    return @()
}

function Add-CloudflareTunnelRoute {
    param(
        [Parameter(Mandatory)]
        [string]$IPAddress,
        
        [Parameter()]
        [string]$Comment
    )
    
    $cidr = "$IPAddress/32"
    Write-Log "Adding tunnel route for $cidr..." -Level "INFO"
    
    # Check if route already exists
    $existingRoutes = Get-CloudflareTunnelRoutes
    $existingRoute = $existingRoutes | Where-Object { $_.network -eq $cidr }
    
    if ($existingRoute) {
        Write-Log "Route $cidr already exists in tunnel" -Level "WARN"
        return $existingRoute
    }
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would add tunnel route: $cidr" -Level "INFO"
        return @{ network = $cidr; id = "dry-run-id" }
    }
    
    $body = @{
        network    = $cidr
        tunnel_id  = $script:Config.CloudflareTunnelId
        comment    = $Comment
    }
    
    $response = Invoke-CloudflareApi -Endpoint "/accounts/$($script:Config.CloudflareAccountId)/teamnet/routes" -Method "POST" -Body $body
    
    if ($response.result) {
        Write-Log "Successfully added tunnel route for $cidr" -Level "SUCCESS"
        return $response.result
    }
    
    throw "Failed to add tunnel route for $cidr"
}

function Get-CloudflareAccessTargets {
    Write-Log "Retrieving existing Access Targets..." -Level "INFO"
    
    $response = Invoke-CloudflareApi -Endpoint "/accounts/$($script:Config.CloudflareAccountId)/infrastructure/targets"
    
    if ($response.result) {
        return $response.result
    }
    
    return @()
}

function New-CloudflareAccessTarget {
    param(
        [Parameter(Mandatory)]
        [string]$Hostname,
        
        [Parameter(Mandatory)]
        [string]$IPAddress
    )
    
    Write-Log "Creating Access Target for $Hostname ($IPAddress)..." -Level "INFO"
    
    # Check if target already exists
    $existingTargets = Get-CloudflareAccessTargets
    $existingTarget = $existingTargets | Where-Object { $_.hostname -eq $Hostname -or $_.ip.ipv4.ip_addr -eq $IPAddress }
    
    if ($existingTarget) {
        Write-Log "Access Target for $Hostname already exists" -Level "WARN"
        return $existingTarget
    }
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would create Access Target: $Hostname -> $IPAddress" -Level "INFO"
        return @{ id = "dry-run-target-id"; hostname = $Hostname }
    }
    
    $body = @{
        hostname = $Hostname
        ip       = @{
            ipv4 = @{
                ip_addr            = $IPAddress
                virtual_network_id = $null
            }
        }
    }
    
    $response = Invoke-CloudflareApi -Endpoint "/accounts/$($script:Config.CloudflareAccountId)/infrastructure/targets" -Method "POST" -Body $body
    
    if ($response.result) {
        Write-Log "Successfully created Access Target for $Hostname" -Level "SUCCESS"
        return $response.result
    }
    
    throw "Failed to create Access Target for $Hostname"
}

function Get-CloudflareAccessApplications {
    Write-Log "Retrieving existing Access Applications..." -Level "INFO"
    
    $response = Invoke-CloudflareApi -Endpoint "/accounts/$($script:Config.CloudflareAccountId)/access/apps"
    
    if ($response.result) {
        return $response.result
    }
    
    return @()
}

function New-CloudflareAccessApplication {
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        
        [Parameter(Mandatory)]
        [string]$PublicHostname,
        
        [Parameter(Mandatory)]
        [string]$TargetHostname,
        
        [Parameter(Mandatory)]
        [string]$TargetId
    )
    
    Write-Log "Creating Access Application: $Name..." -Level "INFO"
    Write-Log "Public Hostname: $PublicHostname" -Level "DEBUG"
    
    # Check if application already exists
    $existingApps = Get-CloudflareAccessApplications
    $existingApp = $existingApps | Where-Object { $_.name -eq $Name }
    
    if ($existingApp) {
        Write-Log "Access Application '$Name' already exists" -Level "WARN"
        return $existingApp
    }
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would create Access Application: $Name with domain $PublicHostname" -Level "INFO"
        return @{ id = "dry-run-app-id"; name = $Name }
    }
    
    $body = @{
        name                       = $Name
        type                       = "self_hosted"
        domain                     = $PublicHostname
        session_duration           = "24h"
        auto_redirect_to_identity  = $false
        app_launcher_visible       = $true
        
        # Browser rendering settings for RDP
        target_criteria = @(
            @{
                target_attributes = @(
                    @{
                        name   = "hostname"
                        values = @($TargetHostname)
                    }
                )
                port = 3389
            }
        )
        
        # Enable browser rendering with RDP protocol
        options_preflight_bypass = $false
        
        # Browser isolation settings for RDP
        policies = @()
    }
    
    $response = Invoke-CloudflareApi -Endpoint "/accounts/$($script:Config.CloudflareAccountId)/access/apps" -Method "POST" -Body $body
    
    if ($response.result) {
        Write-Log "Successfully created Access Application: $Name" -Level "SUCCESS"
        
        # Update app with browser rendering settings
        $appId = $response.result.id
        $updateBody = @{
            name                      = $Name
            type                      = "self_hosted"
            domain                    = $PublicHostname
            session_duration          = "24h"
            app_launcher_visible      = $true
            auto_redirect_to_identity = $false
            
            # Browser RDP rendering configuration
            target_criteria = @(
                @{
                    target_attributes = @(
                        @{
                            name   = "hostname"
                            values = @($TargetHostname)
                        }
                    )
                    port = 3389
                }
            )
        }
        
        $updateResponse = Invoke-CloudflareApi -Endpoint "/accounts/$($script:Config.CloudflareAccountId)/access/apps/$appId" -Method "PUT" -Body $updateBody
        
        return $response.result
    }
    
    throw "Failed to create Access Application: $Name"
}

function Get-CloudflareAccessPolicies {
    param(
        [Parameter(Mandatory)]
        [string]$AppId
    )
    
    $response = Invoke-CloudflareApi -Endpoint "/accounts/$($script:Config.CloudflareAccountId)/access/apps/$AppId/policies"
    
    if ($response.result) {
        return $response.result
    }
    
    return @()
}

function New-CloudflareAccessPolicy {
    param(
        [Parameter(Mandatory)]
        [string]$AppId,
        
        [Parameter(Mandatory)]
        [string]$PolicyName,
        
        [Parameter(Mandatory)]
        [string]$Email
    )
    
    Write-Log "Creating Access Policy: $PolicyName..." -Level "INFO"
    
    # Check if policy already exists
    $existingPolicies = Get-CloudflareAccessPolicies -AppId $AppId
    $existingPolicy = $existingPolicies | Where-Object { $_.name -eq $PolicyName }
    
    if ($existingPolicy) {
        Write-Log "Access Policy '$PolicyName' already exists" -Level "WARN"
        return $existingPolicy
    }
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would create Access Policy: $PolicyName" -Level "INFO"
        return @{ id = "dry-run-policy-id"; name = $PolicyName }
    }
    
    $body = @{
        name       = $PolicyName
        decision   = "allow"
        precedence = 1
        include    = @(
            @{
                email = @{
                    email = $Email
                }
            }
        )
        exclude    = @()
        require    = @()
    }
    
    # Add identity provider requirement if specified
    if (-not [string]::IsNullOrEmpty($script:Config.IdentityProviderId)) {
        $body.include += @{
            identity_provider = @{
                id = $script:Config.IdentityProviderId
            }
        }
    }
    
    $response = Invoke-CloudflareApi -Endpoint "/accounts/$($script:Config.CloudflareAccountId)/access/apps/$AppId/policies" -Method "POST" -Body $body
    
    if ($response.result) {
        Write-Log "Successfully created Access Policy: $PolicyName" -Level "SUCCESS"
        return $response.result
    }
    
    throw "Failed to create Access Policy: $PolicyName"
}

function Remove-CloudflareAccessApplication {
    param(
        [Parameter(Mandatory)]
        [string]$AppId,
        
        [Parameter(Mandatory)]
        [string]$AppName
    )
    
    Write-Log "Removing Access Application: $AppName..." -Level "INFO"
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would remove Access Application: $AppName" -Level "INFO"
        return $true
    }
    
    $response = Invoke-CloudflareApi -Endpoint "/accounts/$($script:Config.CloudflareAccountId)/access/apps/$AppId" -Method "DELETE"
    
    if ($response.success) {
        Write-Log "Successfully removed Access Application: $AppName" -Level "SUCCESS"
        return $true
    }
    
    return $false
}

#endregion

#region Active Directory Functions

function Test-ADConnection {
    Write-Log "Testing Active Directory connection..." -Level "INFO"
    
    try {
        # Check if AD module is available
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw "Active Directory PowerShell module is not installed. Please install RSAT tools."
        }
        
        Import-Module ActiveDirectory -ErrorAction Stop
        
        # Test connection by querying the domain
        $domain = Get-ADDomain -ErrorAction Stop
        Write-Log "Connected to AD Domain: $($domain.DNSRoot)" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to connect to Active Directory: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Get-ADUsersFromGroup {
    Write-Log "Querying Active Directory Group: $($script:Config.ADGroup)..." -Level "INFO"
    
    try {
        $properties = @(
            "mail",
            "EmailAddress", 
            "userPrincipalName",
            $script:Config.ADHostnameAttribute,
            "SamAccountName",
            "DisplayName",
            "Enabled"
        )
        
        # Get members of the AD group
        $groupMembers = Get-ADGroupMember -Identity $script:Config.ADGroup -ErrorAction Stop | 
            Where-Object { $_.objectClass -eq 'user' }
        
        Write-Log "Found $($groupMembers.Count) user member(s) in group" -Level "INFO"
        
        $validUsers = @()
        foreach ($member in $groupMembers) {
            # Get full user details
            $user = Get-ADUser -Identity $member.SamAccountName -Properties $properties -ErrorAction Stop
            
            # Skip disabled users
            if (-not $user.Enabled) {
                Write-Log "Skipping user $($user.SamAccountName): Account is disabled" -Level "WARN"
                continue
            }
            
            # Get email - try multiple attributes
            $email = $user.mail
            if ([string]::IsNullOrEmpty($email)) {
                $email = $user.EmailAddress
            }
            if ([string]::IsNullOrEmpty($email)) {
                $email = $user.userPrincipalName
            }
            
            # Get hostname from custom attribute
            $hostname = $user.$($script:Config.ADHostnameAttribute)
            
            if ([string]::IsNullOrEmpty($email)) {
                Write-Log "Skipping user $($user.SamAccountName): No email address found" -Level "WARN"
                continue
            }
            
            if ([string]::IsNullOrEmpty($hostname)) {
                Write-Log "Skipping user $($user.SamAccountName): No RDP hostname in attribute '$($script:Config.ADHostnameAttribute)'" -Level "WARN"
                continue
            }
            
            $validUsers += [PSCustomObject]@{
                SamAccountName = $user.SamAccountName
                DisplayName    = $user.DisplayName
                Email          = $email
                RDPHostname    = $hostname
            }
            
            Write-Log "Found user: $($user.SamAccountName) - Email: $email - RDP Host: $hostname" -Level "DEBUG"
        }
        
        Write-Log "Found $($validUsers.Count) valid user(s) with email and RDP hostname" -Level "INFO"
        return $validUsers
    }
    catch {
        Write-Log "Failed to query AD Group: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

#endregion

#region DNS Resolution Functions

function Resolve-HostnameToIP {
    param(
        [Parameter(Mandatory)]
        [string]$Hostname
    )
    
    Write-Log "Resolving hostname: $Hostname..." -Level "DEBUG"
    
    try {
        $dnsResult = Resolve-DnsName -Name $Hostname -Type A -ErrorAction Stop
        $ipAddress = ($dnsResult | Where-Object { $_.Type -eq "A" } | Select-Object -First 1).IPAddress
        
        if ([string]::IsNullOrEmpty($ipAddress)) {
            throw "No A record found for $Hostname"
        }
        
        Write-Log "Resolved $Hostname to $ipAddress" -Level "DEBUG"
        return $ipAddress
    }
    catch {
        Write-Log "Failed to resolve hostname $Hostname : $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

#endregion

#region Main Processing Functions

function Get-ExpectedAppName {
    param([string]$Email)
    return "$Email - My PC - Browser RDP"
}

function Get-ExpectedPolicyName {
    param([string]$Email)
    return "$Email - Browser RDP Policy"
}

function Sync-BrowserRDPApplications {
    Write-Log "Starting Browser RDP Application sync..." -Level "INFO"
    
    # Get current AD users
    $adUsers = Get-ADUsersFromGroup
    
    # Get current Cloudflare Access Applications
    $existingApps = Get-CloudflareAccessApplications
    $browserRdpApps = $existingApps | Where-Object { $_.name -match " - My PC - Browser RDP$" }
    
    Write-Log "Found $($browserRdpApps.Count) existing Browser RDP application(s)" -Level "INFO"
    
    # Build lookup of existing apps by email
    $existingAppsByEmail = @{}
    foreach ($app in $browserRdpApps) {
        # Extract email from app name
        if ($app.name -match "^(.+) - My PC - Browser RDP$") {
            $email = $Matches[1]
            $existingAppsByEmail[$email.ToLower()] = $app
        }
    }
    
    # Process new users
    $usersToCreate = @()
    $usersToSkip = @()
    
    foreach ($user in $adUsers) {
        $expectedAppName = Get-ExpectedAppName -Email $user.Email
        
        if ($existingAppsByEmail.ContainsKey($user.Email.ToLower())) {
            Write-Log "User $($user.Email) already has Browser RDP app - skipping" -Level "INFO"
            $usersToSkip += $user
        } else {
            Write-Log "User $($user.Email) needs Browser RDP app - will create" -Level "INFO"
            $usersToCreate += $user
        }
    }
    
    # Find apps to potentially remove (users no longer in OU)
    $adEmails = $adUsers | ForEach-Object { $_.Email.ToLower() }
    $appsToRemove = @()
    
    foreach ($email in $existingAppsByEmail.Keys) {
        if ($email -notin $adEmails) {
            $appsToRemove += @{
                Email = $email
                App   = $existingAppsByEmail[$email]
            }
        }
    }
    
    # Summary
    Write-Log ("=" * 60) -NoTimestamp
    Write-Log "Sync Summary:" -Level "INFO"
    Write-Log "  Users to create: $($usersToCreate.Count)" -Level "INFO"
    Write-Log "  Users already configured: $($usersToSkip.Count)" -Level "INFO"
    Write-Log "  Apps to potentially remove: $($appsToRemove.Count)" -Level "INFO"
    Write-Log ("=" * 60) -NoTimestamp
    
    # Create new users' Browser RDP apps
    if ($usersToCreate.Count -gt 0) {
        Write-Log "Creating Browser RDP applications for new users..." -Level "INFO"
        
        foreach ($user in $usersToCreate) {
            try {
                Write-Log ("-" * 40) -NoTimestamp
                Write-Log "Processing user: $($user.Email) (SamAccountName: $($user.SamAccountName))" -Level "INFO"
                
                # Resolve hostname to IP
                $ipAddress = Resolve-HostnameToIP -Hostname $user.RDPHostname
                
                # Add tunnel route
                Add-CloudflareTunnelRoute -IPAddress $ipAddress -Comment "Browser RDP for $($user.Email)"
                
                # Create DNS record using samAccountName: {samaccountname}-rdp.{zone}
                $dnsRecord = New-CloudflareDnsRecord -SamAccountName $user.SamAccountName
                $publicHostname = $dnsRecord.name
                
                # Create Access Target
                $target = New-CloudflareAccessTarget -Hostname $user.RDPHostname -IPAddress $ipAddress
                
                # Create Access Application with the DNS hostname we just created
                $appName = Get-ExpectedAppName -Email $user.Email
                $app = New-CloudflareAccessApplication `
                    -Name $appName `
                    -PublicHostname $publicHostname `
                    -TargetHostname $user.RDPHostname `
                    -TargetId $target.id
                
                # Create Access Policy
                $policyName = Get-ExpectedPolicyName -Email $user.Email
                New-CloudflareAccessPolicy -AppId $app.id -PolicyName $policyName -Email $user.Email
                
                Write-Log "Successfully configured Browser RDP for $($user.Email) at $publicHostname" -Level "SUCCESS"
            }
            catch {
                Write-Log "Failed to configure Browser RDP for $($user.Email): $($_.Exception.Message)" -Level "ERROR"
            }
        }
    }
    
    # Handle removals with confirmation
    if ($appsToRemove.Count -gt 0) {
        Write-Log "Processing potential removals..." -Level "INFO"
        
        foreach ($removal in $appsToRemove) {
            Write-Host "`n" -NoNewline
            Write-Host "User '$($removal.Email)' is no longer in the AD OU." -ForegroundColor Yellow
            Write-Host "Application: $($removal.App.name)" -ForegroundColor Yellow
            Write-Host "Domain: $($removal.App.domain)" -ForegroundColor Yellow
            
            $confirm = Read-Host "Do you want to DELETE this Browser RDP application and its DNS record? (Y/N)"
            
            if ($confirm -eq 'Y' -or $confirm -eq 'y') {
                try {
                    # Remove DNS record first
                    if ($removal.App.domain) {
                        Remove-CloudflareDnsRecord -DnsName $removal.App.domain
                    }
                    
                    # Remove Access Application
                    Remove-CloudflareAccessApplication -AppId $removal.App.id -AppName $removal.App.name
                    Write-Log "Removed Browser RDP application for $($removal.Email)" -Level "SUCCESS"
                }
                catch {
                    Write-Log "Failed to remove application for $($removal.Email): $($_.Exception.Message)" -Level "ERROR"
                }
            } else {
                Write-Log "Skipped removal of application for $($removal.Email)" -Level "INFO"
            }
        }
    }
    
    Write-Log "Sync completed" -Level "SUCCESS"
}

#endregion

#region Main Entry Point

function Main {
    try {
        # Initialize logging
        $logPath = if ([string]::IsNullOrEmpty($LogPath)) {
            [Environment]::GetEnvironmentVariable("CF_BROWSER_RDP_LOG_PATH")
        } else {
            $LogPath
        }
        if ([string]::IsNullOrEmpty($logPath)) {
            $logPath = $PSScriptRoot
        }
        Initialize-Logging -Path $logPath
        
        if ($DryRun) {
            Write-Log "*** DRY RUN MODE - No changes will be made ***" -Level "WARN"
        }
        
        # Initialize parameters
        Initialize-Parameters
        
        # Test connections
        if (-not (Test-ADConnection)) {
            throw "Failed to connect to Active Directory"
        }
        
        if (-not (Test-CloudflareConnection)) {
            throw "Failed to connect to Cloudflare API"
        }
        
        # Select Cloudflare Tunnel if not specified
        Select-CloudflareTunnel
        
        # Select Cloudflare Zone for DNS records
        Select-CloudflareZone
        
        # Select Identity Provider if not specified
        Select-IdentityProvider
        
        # Run sync
        Sync-BrowserRDPApplications
        
        Write-Log ("=" * 80) -NoTimestamp
        Write-Log "$ScriptName completed successfully" -Level "SUCCESS"
        Write-Log ("=" * 80) -NoTimestamp
    }
    catch {
        Write-Log "Script failed: $($_.Exception.Message)" -Level "ERROR"
        Write-Log $_.ScriptStackTrace -Level "ERROR"
        exit 1
    }
}

# Run main function
Main
