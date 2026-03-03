$uri = "https://scp-pilot-gateway-production-01ff.up.railway.app/evaluate"
$headers = @{ "X-SCP-API-KEY" = "pilot_key_123" }

$bodyObj = @{
  decision_type     = "break_glass"
  decision_owner    = "security_oncall"
  decision_size_usd = 1000000
}
$body = $bodyObj | ConvertTo-Json -Compress

$r1 = Invoke-RestMethod -Method POST -Uri $uri -Headers $headers -ContentType "application/json" -Body $body
$r2 = Invoke-RestMethod -Method POST -Uri $uri -Headers $headers -ContentType "application/json" -Body $body

"verdict: {0}" -f $r1.boundary_snapshot.verdict
"reason : {0}" -f $r1.boundary_snapshot.policy_reason
"commitment_id_1: {0}" -f $r1.commitment_id
"commitment_id_2: {0}" -f $r2.commitment_id
"same_commitment?: {0}" -f ($r1.commitment_id -eq $r2.commitment_id)