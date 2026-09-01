# PhishLens Cyber Defense - Server Starter
Write-Host "🛡️ Starting PhishLens PhishGuard Backend and Web Dashboard..." -ForegroundColor Cyan

$pythonExe = "$env:LOCALAPPDATA\Programs\Python311\python.exe"
if (-not (Test-Path $pythonExe)) {
    $pythonExe = "python"
}

$backendScript = "$PSScriptRoot\backend\app.py"
$dashboardScript = "$PSScriptRoot\dashboard\server.py"

Start-Process -FilePath $pythonExe -ArgumentList $backendScript -NoNewWindow
Start-Process -FilePath $pythonExe -ArgumentList $dashboardScript -NoNewWindow

Write-Host "✅ Backend API running at: http://localhost:5000" -ForegroundColor Green
Write-Host "✅ Cyber Defense Dashboard running at: http://localhost:8080" -ForegroundColor Green
Write-Host "🌐 Open your browser at http://localhost:8080 to interact with PhishLens." -ForegroundColor Yellow
