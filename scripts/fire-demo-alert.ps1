# Fires a demo alert at the production Splunk webhook.
# Reads SPLUNK_WEBHOOK_SECRET from the local .env so no secrets appear on screen.
#
# Usage:
#   .\scripts\fire-demo-alert.ps1 brute_force
#   .\scripts\fire-demo-alert.ps1 data_exfil
#   .\scripts\fire-demo-alert.ps1 port_scan 45.33.32.156

param(
  [string]$EventType = "brute_force",
  [string]$SourceIp = "185.220.101.47"
)

$envFile = Join-Path $PSScriptRoot "..\.env"
$secret = (Get-Content $envFile | Where-Object { $_ -match "^SPLUNK_WEBHOOK_SECRET=" }) -replace "^SPLUNK_WEBHOOK_SECRET=", ""
if (-not $secret) { Write-Error "SPLUNK_WEBHOOK_SECRET not found in .env"; exit 1 }

$details = @{
  brute_force = @{ dest = "auth-service-prod";       message = "847 failed SSH login attempts in 60 seconds" }
  data_exfil  = @{ dest = "database-prod";           message = "Outbound transfer 4.2GB in 3 minutes to external IP" }
  port_scan   = @{ dest = "network-perimeter";       message = "Sequential scan across 3200 ports in 30 seconds" }
  malware     = @{ dest = "workstation-finance-03";  message = "File hash matches known ransomware signature" }
}
$d = $details[$EventType]
if (-not $d) { Write-Error "Unknown event type: $EventType"; exit 1 }

$body = @{
  result = @{
    src_ip     = $SourceIp
    dest       = $d.dest
    event_type = $EventType
    severity   = "high"
    message    = $d.message
    count      = "1"
  }
} | ConvertTo-Json -Depth 3

$url = "https://soc-agent-production.up.railway.app/webhook/splunk?token=$secret"
Invoke-RestMethod -Method Post -Uri $url -ContentType "application/json" -Body $body
Write-Host "Alert sent: $EventType from $SourceIp -> $($d.dest)"
