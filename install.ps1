# TempS3 Windows Installer Script
# Usage: iwr -useb https://raw.githubusercontent.com/yourusername/temps3/main/install.ps1 | iex

param(
    [string]$InstallDir = "$env:USERPROFILE\.local\bin",
    [switch]$Force
)

# Configuration
$Repo = "killcod3/temps3"
$Version = "v0.1.0"
$Platform = "x86_64-pc-windows-gnu"
$Archive = "temps3-$Version-$Platform.zip"
$Url = "https://github.com/$Repo/releases/download/$Version/$Archive"

# Colors
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    } else {
        $input | Write-Output
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

function Write-Info { Write-ColorOutput Blue "🔵 $args" }
function Write-Success { Write-ColorOutput Green "✅ $args" }
function Write-Warning { Write-ColorOutput Yellow "⚠️ $args" }
function Write-Error { Write-ColorOutput Red "❌ $args" }

try {
    Write-Info "TempS3 Windows Installer"
    Write-Info "Installing TempS3 $Version for Windows"
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Error "PowerShell 5.0 or higher is required"
        exit 1
    }
    
    # Create install directory
    if (!(Test-Path $InstallDir)) {
        Write-Info "Creating install directory: $InstallDir"
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    }
    
    # Check if already installed
    $ExePath = Join-Path $InstallDir "temps3.exe"
    if ((Test-Path $ExePath) -and !$Force) {
        $response = Read-Host "TempS3 is already installed. Overwrite? [y/N]"
        if ($response -ne "y" -and $response -ne "Y") {
            Write-Warning "Installation cancelled"
            exit 0
        }
    }
    
    # Create temporary directory
    $TempDir = Join-Path $env:TEMP "temps3-install-$(Get-Random)"
    New-Item -ItemType Directory -Force -Path $TempDir | Out-Null
    
    try {
        # Download archive
        Write-Info "Downloading $Archive"
        $ArchivePath = Join-Path $TempDir $Archive
        
        if (Get-Command Invoke-WebRequest -ErrorAction SilentlyContinue) {
            Invoke-WebRequest -Uri $Url -OutFile $ArchivePath -UseBasicParsing
        } else {
            Write-Error "Invoke-WebRequest not available. Please update PowerShell."
            exit 1
        }
        
        # Extract archive
        Write-Info "Extracting archive"
        if (Get-Command Expand-Archive -ErrorAction SilentlyContinue) {
            Expand-Archive -Path $ArchivePath -DestinationPath $TempDir -Force
        } else {
            # Fallback for older PowerShell
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($ArchivePath, $TempDir)
        }
        
        # Install binary
        Write-Info "Installing to $InstallDir"
        $SourceExe = Join-Path $TempDir "temps3.exe"
        if (Test-Path $SourceExe) {
            Copy-Item $SourceExe $ExePath -Force
        } else {
            Write-Error "Binary not found in archive"
            exit 1
        }
        
        Write-Success "TempS3 installed successfully!"
        
        # Check PATH
        $UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
        if ($UserPath -notlike "*$InstallDir*") {
            Write-Warning "$InstallDir is not in your PATH"
            $response = Read-Host "Add $InstallDir to your PATH? [Y/n]"
            if ($response -ne "n" -and $response -ne "N") {
                Write-Info "Adding $InstallDir to user PATH"
                $NewPath = "$InstallDir;$UserPath"
                [Environment]::SetEnvironmentVariable("PATH", $NewPath, "User")
                Write-Success "PATH updated. Please restart your terminal."
            }
        }
        
        Write-Success "🎉 Installation complete!"
        Write-Info "Run 'temps3 config' to get started."
        
    } finally {
        # Cleanup
        if (Test-Path $TempDir) {
            Remove-Item $TempDir -Recurse -Force
        }
    }
    
} catch {
    Write-Error "Installation failed: $($_.Exception.Message)"
    exit 1
}
