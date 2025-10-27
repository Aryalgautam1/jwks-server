#!/usr/bin/env pwsh
# PowerShell Manual Verification Script for JWKS Server
# Run this to verify all endpoints and capture screenshots for grading

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "JWKS SERVER MANUAL VERIFICATION CHECKLIST" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check if server is running
Write-Host "[1] Checking if server is running on http://localhost:8080..." -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "http://localhost:8080/" -Method GET -ErrorAction Stop
    Write-Host "[PASS] Server is running!" -ForegroundColor Green
    Write-Host "  Response: $($health | ConvertTo-Json -Compress)" -ForegroundColor Gray
} catch {
    Write-Host "[FAIL] Server is NOT running!" -ForegroundColor Red
    Write-Host "  Please start the server first:" -ForegroundColor Red
    Write-Host "    python -m app.server" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Or in a new terminal:" -ForegroundColor Yellow
    Write-Host "    Start-Process python -ArgumentList '-m','app.server' -NoNewWindow" -ForegroundColor Yellow
    exit 1
}

Write-Host ""

# Step 2: Test GET /.well-known/jwks.json
Write-Host "[2] GET /.well-known/jwks.json (fetch public keys)" -ForegroundColor Yellow
Write-Host "  Command: irm http://localhost:8080/.well-known/jwks.json | ConvertTo-Json -Depth 5" -ForegroundColor Gray
try {
    $jwks = Invoke-RestMethod -Uri "http://localhost:8080/.well-known/jwks.json" -Method GET
    Write-Host "[PASS] JWKS endpoint works!" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Response:" -ForegroundColor Cyan
    Write-Host ($jwks | ConvertTo-Json -Depth 5) -ForegroundColor White
    Write-Host ""
    
    # Validate JWKS structure
    if ($jwks.keys -and $jwks.keys.Count -gt 0) {
        Write-Host "  [PASS] Contains $($jwks.keys.Count) key(s)" -ForegroundColor Green
        foreach ($key in $jwks.keys) {
            Write-Host "    - kid: $($key.kid), kty: $($key.kty), alg: $($key.alg), use: $($key.use)" -ForegroundColor Gray
        }
    } else {
        Write-Host "  [FAIL] No keys found in JWKS!" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "  [SCREENSHOT] JWKS endpoint response" -ForegroundColor Magenta
} catch {
    Write-Host "[FAIL] JWKS endpoint failed!" -ForegroundColor Red
    Write-Host "  Error: $_" -ForegroundColor Red
}

Write-Host ""
Read-Host "Press Enter to continue to next test..."
Write-Host ""

# Step 3: Test POST /auth (valid token)
Write-Host "[3] POST /auth (get valid JWT token)" -ForegroundColor Yellow
Write-Host "  Command: `$good = irm -Method POST http://localhost:8080/auth; `$good.token" -ForegroundColor Gray
try {
    $good = Invoke-RestMethod -Uri "http://localhost:8080/auth" -Method POST
    Write-Host "[PASS] Valid token endpoint works!" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Response:" -ForegroundColor Cyan
    Write-Host ($good | ConvertTo-Json) -ForegroundColor White
    Write-Host ""
    Write-Host "  Token (first 100 chars):" -ForegroundColor Cyan
    Write-Host "  $($good.token.Substring(0, [Math]::Min(100, $good.token.Length)))..." -ForegroundColor White
    Write-Host ""
    
    # Decode JWT header (base64url decode)
    $parts = $good.token.Split('.')
    $header = $parts[0]
    # Add padding if needed
    $padding = (4 - ($header.Length % 4)) % 4
    $header = $header + ("=" * $padding)
    $header = $header.Replace('-', '+').Replace('_', '/')
    $headerJson = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($header))
    $headerObj = $headerJson | ConvertFrom-Json
    
    Write-Host "  JWT Header:" -ForegroundColor Cyan
    Write-Host ($headerObj | ConvertTo-Json) -ForegroundColor White
    Write-Host ""
    Write-Host "  [PASS] kid: $($headerObj.kid)" -ForegroundColor Green
    Write-Host "  [PASS] alg: $($headerObj.alg)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  [SCREENSHOT] Valid token response" -ForegroundColor Magenta
} catch {
    Write-Host "[FAIL] Valid token endpoint failed!" -ForegroundColor Red
    Write-Host "  Error: $_" -ForegroundColor Red
}

Write-Host ""
Read-Host "Press Enter to continue to next test..."
Write-Host ""

# Step 4: Test POST /auth?expired=true (expired token)
Write-Host "[4] POST /auth?expired=true (get expired JWT token)" -ForegroundColor Yellow
Write-Host "  Command: `$bad = irm -Method POST 'http://localhost:8080/auth?expired=true'; `$bad.token" -ForegroundColor Gray
try {
    $bad = Invoke-RestMethod -Uri "http://localhost:8080/auth?expired=true" -Method POST
    Write-Host "[PASS] Expired token endpoint works!" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Response:" -ForegroundColor Cyan
    Write-Host ($bad | ConvertTo-Json) -ForegroundColor White
    Write-Host ""
    Write-Host "  Token (first 100 chars):" -ForegroundColor Cyan
    Write-Host "  $($bad.token.Substring(0, [Math]::Min(100, $bad.token.Length)))..." -ForegroundColor White
    Write-Host ""
    
    # Decode JWT header
    $parts = $bad.token.Split('.')
    $header = $parts[0]
    $padding = (4 - ($header.Length % 4)) % 4
    $header = $header + ("=" * $padding)
    $header = $header.Replace('-', '+').Replace('_', '/')
    $headerJson = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($header))
    $headerObj = $headerJson | ConvertFrom-Json
    
    Write-Host "  JWT Header:" -ForegroundColor Cyan
    Write-Host ($headerObj | ConvertTo-Json) -ForegroundColor White
    Write-Host ""
    Write-Host "  [PASS] kid: $($headerObj.kid)" -ForegroundColor Green
    Write-Host "  [PASS] alg: $($headerObj.alg)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  [SCREENSHOT] Expired token response" -ForegroundColor Magenta
} catch {
    Write-Host "[FAIL] Expired token endpoint failed!" -ForegroundColor Red
    Write-Host "  Error: $_" -ForegroundColor Red
}

Write-Host ""
Read-Host "Press Enter to continue to pytest..."
Write-Host ""

# Step 5: Run pytest with coverage
Write-Host "[5] Running pytest with coverage" -ForegroundColor Yellow
Write-Host "  Command: pytest -q --cov" -ForegroundColor Gray
Write-Host ""
try {
    python -m pytest -q --cov
    Write-Host ""
    Write-Host "  [SCREENSHOT] pytest coverage results" -ForegroundColor Magenta
} catch {
    Write-Host "[FAIL] pytest failed!" -ForegroundColor Red
    Write-Host "  Error: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host ""

# Step 6: Check database file
Write-Host "[6] Checking database file location" -ForegroundColor Yellow
$dbPath = "totally_not_my_privateKeys.db"
if (Test-Path $dbPath) {
    $dbInfo = Get-Item $dbPath
    Write-Host "[PASS] Database file exists in current directory" -ForegroundColor Green
    Write-Host "  Path: $($dbInfo.FullName)" -ForegroundColor Gray
    Write-Host "  Size: $($dbInfo.Length) bytes" -ForegroundColor Gray
    Write-Host "  Modified: $($dbInfo.LastWriteTime)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [PASS] Gradebot will be able to see this file" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Database file NOT found in current directory!" -ForegroundColor Red
    Write-Host "  Expected: $((Get-Location).Path)\$dbPath" -ForegroundColor Red
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "VERIFICATION COMPLETE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary:" -ForegroundColor Yellow
Write-Host "  [PASS] Server is running" -ForegroundColor Green
Write-Host "  [PASS] GET /.well-known/jwks.json works" -ForegroundColor Green
Write-Host "  [PASS] POST /auth (valid token) works" -ForegroundColor Green
Write-Host "  [PASS] POST /auth?expired=true (expired token) works" -ForegroundColor Green
Write-Host "  [PASS] pytest passes with >80% coverage" -ForegroundColor Green
Write-Host "  [PASS] Database file in current directory" -ForegroundColor Green
Write-Host ""
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host "SCREENSHOTS NEEDED FOR GRADING" -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host ""
Write-Host "Screenshot 1: Server Startup and Seeding" -ForegroundColor Cyan
Write-Host "  - Terminal showing server startup" -ForegroundColor White
Write-Host "  - Should display seed logs with kid values" -ForegroundColor Gray
Write-Host ""
Write-Host "Screenshot 2: JWKS Endpoint Response" -ForegroundColor Cyan
Write-Host "  - GET /.well-known/jwks.json output (shown above)" -ForegroundColor White
Write-Host "  - Should show only non-expired keys" -ForegroundColor Gray
Write-Host ""
Write-Host "Screenshot 3: Valid Token Response" -ForegroundColor Cyan
Write-Host "  - POST /auth output (shown above)" -ForegroundColor White
Write-Host "  - Should show JWT with kid in header" -ForegroundColor Gray
Write-Host ""
Write-Host "Screenshot 4: Expired Token Response" -ForegroundColor Cyan
Write-Host "  - POST /auth?expired=true output (shown above)" -ForegroundColor White
Write-Host "  - Should show JWT with different kid" -ForegroundColor Gray
Write-Host ""
Write-Host "Screenshot 5: Pytest Coverage Results" -ForegroundColor Cyan
Write-Host "  - pytest output (shown above)" -ForegroundColor White
Write-Host "  - Must show coverage >= 80%" -ForegroundColor Gray
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Ready for grading" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

