# Helper script to prepare SSH key (if missing), show public key, add remote and push project to GitHub
# USAGE: Open PowerShell as your user and run: .\push_to_github.ps1

param(
    [string]$sshUrl = 'git@github.com:pth231/Project-.git',
    [string]$gitUser = '',
    [string]$gitEmail = ''
)

$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "Project dir: $projectDir"

# 1) Ensure SSH key exists
$pubKeyPath = "$env:USERPROFILE\.ssh\id_ed25519.pub"
if (-Not (Test-Path $pubKeyPath)) {
    Write-Host "No SSH key found at $pubKeyPath. Generating a new ed25519 key..." -ForegroundColor Yellow
    ssh-keygen -t ed25519 -C "your_email@example.com" -f "$env:USERPROFILE\.ssh\id_ed25519"
    Write-Host "SSH key generated." -ForegroundColor Green
} else {
    Write-Host "Found existing SSH public key: $pubKeyPath" -ForegroundColor Green
}

# Show public key and copy to clipboard
Write-Host "\n=== Public key (add this to GitHub -> Settings -> SSH and GPG keys) ===" -ForegroundColor Cyan
Get-Content $pubKeyPath
Get-Content $pubKeyPath | Set-Clipboard
Write-Host "(Public key copied to clipboard)" -ForegroundColor Cyan

Write-Host "\nPlease add the above public key to the GitHub repository owner's account (Settings → SSH and GPG keys → New SSH key)." -ForegroundColor Yellow
Write-Host "Press Enter after you have added the key to GitHub (or Ctrl+C to abort)."
Read-Host | Out-Null

# 2) Configure git user if provided
Set-Location $projectDir
if ($gitUser -ne '') { git config user.name "$gitUser" }
if ($gitEmail -ne '') { git config user.email "$gitEmail" }

# 3) Initialize repo if necessary
if (-Not (Test-Path (Join-Path $projectDir '.git'))) {
    Write-Host "Initializing new git repository..." -ForegroundColor Cyan
    git init
} else {
    Write-Host ".git already exists" -ForegroundColor Green
}

# 4) Add remote (replace if exists)
$existingRemote = git remote | Where-Object { $_ -eq 'origin' }
if ($existingRemote) {
    Write-Host "Remote 'origin' already exists. Setting URL to $sshUrl" -ForegroundColor Yellow
    git remote set-url origin $sshUrl
} else {
    Write-Host "Adding remote origin -> $sshUrl" -ForegroundColor Cyan
    git remote add origin $sshUrl
}

# 5) Add files, commit, push
Write-Host "Adding files and committing..." -ForegroundColor Cyan
git add .
try {
    git commit -m "Phase 0: Skeleton API with crypto utilities and demo"
} catch {
    Write-Host "Nothing to commit or commit failed: $_" -ForegroundColor Yellow
}

# Ensure branch main
git branch -M main

Write-Host "Pushing to origin main..." -ForegroundColor Cyan
try {
    git push -u origin main
    Write-Host "Push completed (or request for SSH auth shown above)." -ForegroundColor Green
} catch {
    Write-Host "Push failed: $_" -ForegroundColor Red
    Write-Host "Common reasons: wrong SSH URL, SSH key not added to GitHub, or network issues." -ForegroundColor Yellow
}

Write-Host "\nNext: verify on GitHub that your files appear in the repository." -ForegroundColor Cyan
