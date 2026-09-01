# Script to push PhishLens to GitHub
$gitPath = "$env:LOCALAPPDATA\Programs\Git\cmd"
if (Test-Path $gitPath) {
    $env:PATH = "$env:PATH;$gitPath"
}

Write-Host "🚀 Pushing PhishLens to https://github.com/hemashri478-stack/phishing-net.git..." -ForegroundColor Cyan
git push -u origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Successfully pushed to GitHub!" -ForegroundColor Green
    Write-Host "🌐 Next step: Go to https://vercel.com/new and click Deploy!" -ForegroundColor Yellow
} else {
    Write-Host "⚠️ If authentication failed, please ensure you are logged into GitHub or use a Personal Access Token." -ForegroundColor Red
}
