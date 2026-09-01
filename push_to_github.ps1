# Script to push PhishLens to GitHub
$gitPath = "$env:LOCALAPPDATA\Programs\Git\cmd"
if (Test-Path $gitPath) {
    $env:PATH = "$env:PATH;$gitPath"
}

if (Test-Path "shadowlens-main\.git") {
    Set-Location "shadowlens-main"
}

Write-Host "🚀 Pushing PhishLens to https://github.com/hemashri478-stack/phishing-mail.git..." -ForegroundColor Cyan
git push -u origin main --force

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Successfully pushed to GitHub!" -ForegroundColor Green
    Write-Host "🌐 Next step: Go to https://vercel.com/new and click Deploy!" -ForegroundColor Yellow
} else {
    Write-Host "⚠️ If authentication failed, please ensure you are logged into GitHub or use a Personal Access Token." -ForegroundColor Red
}
