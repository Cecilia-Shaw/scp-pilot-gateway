$uri = "https://scp-pilot-gateway-production-01ff.up.railway.app/evaluate"
$headers = @{ "X-SCP-API-KEY" = "pilot_key_123" }

function Call-Gate($n) {
  $obj = @{
    decision_type = "trade"
    decision_owner = "risk_team"
    decision_size_usd = $n
  }
  $body = $obj | ConvertTo-Json -Compress
  $r = Invoke-RestMethod -Method POST -Uri $uri -Headers $headers -ContentType "application/json" -Body $body
  "{0} -> {1} | {2}" -f $n, $r.boundary_snapshot.verdict, $r.boundary_snapshot.policy_reason
  "commitment_id: {0}" -f $r.commitment_id
  "signature:     {0}" -f $r.signature
  ""
}

Call-Gate 100000
Call-Gate 1000000
Call-Gate 10000000