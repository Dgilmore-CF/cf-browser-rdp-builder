# Cloudflare Browser-Based RDP Management Script

## Overview

This PowerShell script automates the management of Cloudflare Browser-Based RDP Access Applications synced with Active Directory OU membership. It creates, updates, and removes Cloudflare Access applications based on users present in a specified AD OU.

---

## Prerequisites

### System Requirements

- **PowerShell**: Version 5.1 or higher (PowerShell 7+ recommended)
- **Operating System**: Windows Server 2012 R2+ or Windows 10+ with RSAT tools
- **Network Access**: 
  - Connectivity to Active Directory Domain Controllers
  - HTTPS access to `api.cloudflare.com`
  - DNS resolution capability for RDP hostnames

### Required PowerShell Modules

```powershell
# Active Directory Module (part of RSAT)
# Install on Windows Server:
Install-WindowsFeature -Name RSAT-AD-PowerShell

# Install on Windows 10/11:
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

---

## Active Directory Requirements

### Permissions Required

The account running this script needs the following AD permissions:

| Permission | Scope | Purpose |
|------------|-------|---------|
| **Read** | Target OU and descendant user objects | Query user accounts |
| **Read Property: mail** | User objects | Retrieve email addresses |
| **Read Property: userPrincipalName** | User objects | Fallback email source |
| **Read Property: [Custom Attribute]** | User objects | Retrieve RDP hostname |

### Recommended AD Setup

1. **Create a dedicated service account** for running this script
2. **Delegate read permissions** to the specific OU containing RDP users
3. **Use a Group Managed Service Account (gMSA)** for enhanced security in scheduled task scenarios

### Custom Attribute Configuration

The script reads RDP hostnames from a custom AD attribute. Common options:

| Attribute | Description |
|-----------|-------------|
| `extensionAttribute1` - `extensionAttribute15` | Built-in Exchange extension attributes |
| `msDS-cloudExtensionAttribute1` - `msDS-cloudExtensionAttribute20` | Cloud extension attributes |
| Custom schema extension | Requires AD schema modification |

**Example: Setting the RDP hostname for a user:**
```powershell
Set-ADUser -Identity "jsmith" -Add @{extensionAttribute1 = "jsmith-workstation.internal.domain.com"}
```

---

## Cloudflare API Token Requirements

### Creating the API Token

1. Log into the [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Navigate to **My Profile** → **API Tokens**
3. Click **Create Token**
4. Select **Create Custom Token**

### Required Permissions

Configure the following permissions for your API token:

| Permission Category | Permission | Access Level | Purpose |
|---------------------|------------|--------------|---------|
| **Account** | Access: Apps and Policies | Edit | Create/modify/delete Access Applications and Policies |
| **Account** | Access: Organizations, Identity Providers, and Groups | Read | List Identity Providers for interactive selection |
| **Account** | Access: Infrastructure Targets | Edit | Create/modify Access Targets |
| **Account** | Cloudflare Tunnel | Read | List available tunnels for interactive selection |
| **Account** | Cloudflare Tunnel | Edit | Add CIDR routes to tunnel configuration |
| **Account** | Account Settings | Read | Verify account access |
| **Zone** | Zone | Read | List available zones for interactive selection |
| **Zone** | DNS | Edit | Create/delete DNS records for user RDP hostnames |

### Token Configuration Summary

```
Token Name: Browser RDP Management Script
Permissions:
  Account - Access: Apps and Policies - Edit
  Account - Access: Organizations, Identity Providers, and Groups - Read  
  Account - Access: Infrastructure Targets - Edit
  Account - Cloudflare Tunnel - Read
  Account - Cloudflare Tunnel - Edit
  Account - Account Settings - Read
  Zone - Zone - Read
  Zone - DNS - Edit

Zone Resources:
  Include - All zones (or specific zones where DNS records will be created)

Account Resources:
  Include - [Your Account Name]

Client IP Address Filtering (Recommended):
  Include - [IP of server running the script]

TTL (Optional):
  Set expiration date based on your security requirements
```

### Token Permission Details

#### Access: Apps and Policies (Edit)
- **Create** self-hosted Access Applications
- **Update** application settings (browser rendering, target criteria)
- **Delete** applications for removed users
- **Create/Read/Delete** Access Policies

#### Access: Organizations, Identity Providers, and Groups (Read)
- **List** configured Identity Providers
- **Read** IdP configuration for policy creation

#### Access: Infrastructure Targets (Edit)
- **Create** infrastructure targets (hostname + IP mappings)
- **List** existing targets to avoid duplicates
- **Delete** targets when applications are removed

#### Cloudflare Tunnel (Edit)
- **Add** CIDR routes (/32) to tunnel configuration
- **List** existing routes to avoid duplicates
- **Remove** routes when applications are removed

#### Zone (Read)
- **List** available zones for interactive selection
- **Read** zone details to get zone name for DNS record creation

#### DNS (Edit)
- **Create** CNAME DNS records in format `{samaccountname}-rdp.{zonename}`
- **List** existing DNS records to avoid duplicates
- **Delete** DNS records when applications are removed

---

## Environment Variables

The script supports configuration via environment variables for automation scenarios:

| Variable | Description | Example |
|----------|-------------|---------|
| `CF_ACCOUNT_ID` | Cloudflare Account ID | `abcd1234567890` |
| `CF_API_TOKEN` | Cloudflare API Token | `your-api-token` |
| `CF_TUNNEL_ID` | Cloudflare Tunnel ID | `12345678-abcd-...` |
| `CF_ZONE_ID` | Cloudflare Zone ID for DNS records | `12345678-abcd-...` |
| `CF_IDP_ID` | Identity Provider ID | `12345678-abcd-...` |
| `CF_BROWSER_RDP_AD_OU` | AD OU Distinguished Name | `OU=RDPUsers,DC=contoso,DC=com` |
| `CF_BROWSER_RDP_AD_HOSTNAME_ATTR` | AD attribute for RDP hostname | `extensionAttribute1` |
| `CF_BROWSER_RDP_LOG_PATH` | Log file directory | `C:\Logs\BrowserRDP` |

### Setting Environment Variables

**PowerShell (Current Session):**
```powershell
$env:CF_ACCOUNT_ID = "your-account-id"
$env:CF_API_TOKEN = "your-api-token"
```

**PowerShell (Persistent - User):**
```powershell
[Environment]::SetEnvironmentVariable("CF_ACCOUNT_ID", "your-account-id", "User")
```

**PowerShell (Persistent - Machine):**
```powershell
[Environment]::SetEnvironmentVariable("CF_ACCOUNT_ID", "your-account-id", "Machine")
```

---

## Cloudflare Prerequisites

Before running the script, ensure the following are configured in Cloudflare:

### 1. Cloudflare Tunnel

A Cloudflare Tunnel must be created and running:

```bash
# Create tunnel (if not exists)
cloudflared tunnel create browser-rdp-tunnel

# Configure tunnel to route traffic
# The script will add /32 CIDR routes automatically
```

**Required Tunnel Configuration:**
- Tunnel must be in a running state
- Tunnel must be associated with your Cloudflare account
- Note the Tunnel ID (UUID format)
- The script will automatically add /32 CIDR routes for each user's RDP host IP

**Note:** You do NOT need to configure a Public Hostname on the tunnel for Browser-Based RDP. The script creates DNS A records and adds CIDR routes - Cloudflare handles the routing through the Access Application and Infrastructure Targets.

### 2. Identity Provider

At least one Identity Provider must be configured:

1. Go to **Zero Trust** → **Settings** → **Authentication**
2. Add an Identity Provider (Azure AD, Okta, Google, etc.)
3. Note the IdP ID if you want to specify it via parameter

---

## Usage Examples

### Interactive Mode
```powershell
.\Manage-CloudflareBrowserRDP.ps1
```
The script will prompt for all required values.

### Command Line Parameters
```powershell
.\Manage-CloudflareBrowserRDP.ps1 `
    -ADOrganizationalUnit "OU=RDPUsers,DC=contoso,DC=com" `
    -ADHostnameAttribute "extensionAttribute1" `
    -CloudflareAccountId "your-account-id" `
    -CloudflareApiToken "your-api-token" `
    -CloudflareTunnelId "your-tunnel-id" `
    -CloudflareZoneId "your-zone-id" `
    -IdentityProviderId "your-idp-id"
```

### Using Environment Variables
```powershell
# Set environment variables first
$env:CF_ACCOUNT_ID = "your-account-id"
$env:CF_API_TOKEN = "your-api-token"
$env:CF_TUNNEL_ID = "your-tunnel-id"
$env:CF_ZONE_ID = "your-zone-id"
$env:CF_BROWSER_RDP_AD_OU = "OU=RDPUsers,DC=contoso,DC=com"
$env:CF_BROWSER_RDP_AD_HOSTNAME_ATTR = "extensionAttribute1"
$env:CF_IDP_ID = "your-idp-id"

# Run script
.\Manage-CloudflareBrowserRDP.ps1
```

### Dry Run Mode
```powershell
.\Manage-CloudflareBrowserRDP.ps1 -DryRun
```
Shows what would be created/deleted without making changes.

---

## What the Script Creates

For each user in the AD OU, the script creates:

### 1. Tunnel CIDR Route
- **Network**: `{resolved-ip}/32`
- **Comment**: `Browser RDP for {email}`

### 2. DNS A Record
- **Name**: `{samaccountname}-rdp.{zonename}` (e.g., `jsmith-rdp.example.com`)
- **Target**: `240.0.0.0`
- **Proxied**: Yes

### 3. Infrastructure Target
- **Hostname**: Value from AD custom attribute (internal RDP host)
- **IP Address**: Resolved from hostname

### 4. Access Application
- **Name**: `{email} - My PC - Browser RDP`
- **Type**: Self-Hosted
- **Domain**: `{samaccountname}-rdp.{zonename}` (the DNS record created above)
- **Browser Rendering**: RDP protocol on port 3389
- **App Launcher**: Visible (enabled)

### 5. Access Policy
- **Name**: `{email} - Browser RDP Policy`
- **Decision**: Allow
- **Include Rule**: Email equals user's email address
- **Identity Provider**: Selected IdP (if specified)

---

## Sync Behavior

### Adding Users
- Script detects users in AD OU without corresponding Cloudflare apps
- Automatically creates all required resources
- Skips users who already have apps configured

### Removing Users
- Script detects apps for users no longer in the AD OU
- **Prompts for confirmation** before each deletion
- User can approve or skip each removal individually

### Idempotency
- Safe to run multiple times
- Existing configurations are detected and preserved
- Only creates resources that don't exist

---

## Logging

Logs are written to:
- **Console**: Color-coded by severity
- **File**: `Manage-CloudflareBrowserRDP_YYYYMMDD_HHmmss.log`

Log levels:
- **INFO**: Normal operations
- **SUCCESS**: Completed operations (green)
- **WARN**: Non-critical issues (yellow)
- **ERROR**: Failures (red)
- **DEBUG**: Detailed information

---

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "AD module not found" | RSAT not installed | Install RSAT AD PowerShell tools |
| "Access denied to OU" | Insufficient AD permissions | Grant read access to service account |
| "API authentication failed" | Invalid/expired token | Regenerate Cloudflare API token |
| "Tunnel not found" | Wrong tunnel ID or permissions | Verify tunnel ID and token permissions |
| "Cannot resolve hostname" | DNS issue | Verify hostname is resolvable from script host |

### Verifying API Token Permissions

```powershell
# Test token validity
$headers = @{ "Authorization" = "Bearer $env:CF_API_TOKEN" }
Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/user/tokens/verify" -Headers $headers
```

### Checking AD Connectivity

```powershell
# Test AD module
Import-Module ActiveDirectory
Get-ADDomain

# Test OU access
Get-ADUser -SearchBase "OU=RDPUsers,DC=contoso,DC=com" -Filter * -ResultSetSize 1
```

---

## Security Considerations

1. **API Token Storage**: Never commit tokens to source control. Use environment variables or secure vaults.

2. **Least Privilege**: Create a dedicated API token with only the required permissions.

3. **Token Rotation**: Regularly rotate API tokens and update configurations.

4. **Audit Logging**: Review script logs and Cloudflare audit logs for unexpected changes.

5. **Network Security**: Restrict API token usage to specific IP addresses if possible.

6. **AD Service Account**: Use a dedicated, low-privilege service account for AD queries.

---

## Scheduled Execution

For automated sync, create a scheduled task:

```powershell
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -File C:\Scripts\Manage-CloudflareBrowserRDP.ps1"

$trigger = New-ScheduledTaskTrigger -Daily -At "6:00AM"

$principal = New-ScheduledTaskPrincipal -UserId "DOMAIN\ServiceAccount" -LogonType Password

Register-ScheduledTask -TaskName "Sync Browser RDP Apps" `
    -Action $action -Trigger $trigger -Principal $principal
```

**Note**: For scheduled execution, ensure all parameters are provided via environment variables or hard-coded in a wrapper script, as interactive prompts won't work.

---

## Support

For issues with:
- **Cloudflare API**: [Cloudflare Developer Documentation](https://developers.cloudflare.com/api/)
- **Cloudflare Access**: [Zero Trust Documentation](https://developers.cloudflare.com/cloudflare-one/)
- **Active Directory**: [Microsoft AD Documentation](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/)
