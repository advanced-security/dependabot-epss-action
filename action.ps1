<#
.SYNOPSIS
Action to detect if any open Dependabot alerts exceed a specified EPSS (Ecosystem Package Security Score) threshold.  See EPSS at https://www.first.org/epss
.DESCRIPTION
Requirements:
- GITHUB_TOKEN env variable with repo scope or security_events scope. For public repositories, you may instead use the public_repo scope.
.EXAMPLE
# PS>gh auth token # <-- Easy to grab a local auth token to test with from here!
# PS>Write-Host "initializing local run! Ensure you provide a valid GITHUB_TOKEN otherwise you will get a 401!!! "
# $VerbosePreference = 'SilentlyContinue'
# $env:GITHUB_TOKEN = gh auth token
# $env:GITHUB_REPOSITORY = 'vulna-felickz/log4shell-vulnerable-app'
# CLEAR GLOBAL VARIABLES!
# Remove-Variable * -ErrorAction SilentlyContinue;
# PS> action.ps1

.PARAMETER GitHubToken
    The GitHub PAT that is used to authenticate to GitHub GH CLI (uses the envioronment value GH_TOKEN).

.PARAMETER EPSS_Threshold
Specifies the EPSS (Ecosystem Package Security Score) threshold value. The default threshold is set to 0.6.

.NOTES
The highest EPSS score as of March 2, 2024 is 0.97565, belonging to CVE-2021-44228 aka Log4j.

See EPSS at https://www.first.org/epss
Jay Jacobs, Sasha Romanosky, Benjamin Edwards, Michael Roytman, Idris Adjerid, (2021), Exploit Prediction Scoring System, Digital Threats Research and Practice, 2(3)

.LINK
https://github.com/advanced-security/dependabot-epss-action
#>

#add parameter for EPSS Threshold (default to 0.6)
param(
    #The highest EPSS score is 0.97565, belonging to CVE-2021-44228 aka Log4j
    [string]$GitHubToken = $null,
    [string]$EPSS_Threshold = "0.6"
)

function Decompress-GZip($infile, $outfile) {
    $inStream = New-Object System.IO.FileStream $inFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
    $gzipStream = New-Object System.IO.Compression.GzipStream $inStream, ([IO.Compression.CompressionMode]::Decompress)
    $outStream = New-Object System.IO.FileStream $outFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
    $buffer = New-Object byte[](1024)
    while (($read = $gzipStream.Read($buffer, 0, 1024)) -gt 0) {
        $outStream.Write($buffer, 0, $read)
    }
    $gzipStream.Close()
    $outStream.Close()
    $inStream.Close()
}

# Handle `Untrusted repository` prompt
Set-PSRepository PSGallery -InstallationPolicy Trusted

#check if GitHubActions module is installed
if (Get-Module -ListAvailable -Name GitHubActions -ErrorAction SilentlyContinue) {
    Write-ActionDebug "GitHubActions module is installed"
}
else {
    #directly to output here before module loaded to support Write-ActionInfo
    Write-Output "GitHubActions module is not installed.  Installing from Gallery..."
    Install-Module -Name GitHubActions
}

#check if PowerShellForGitHub module is installed
if (Get-Module -ListAvailable -Name PowerShellForGitHub -ErrorAction SilentlyContinue) {
    Write-ActionDebug "PowerShellForGitHub module is installed"
}
else {
    Write-ActionInfo "PowerShellForGitHub module is not installed.  Installing from Gallery..."
    Install-Module -Name PowerShellForGitHub

    #Disable Telemetry since we are accessing sensitive apis - https://github.com/microsoft/PowerShellForGitHub/blob/master/USAGE.md#telemetry
    Set-GitHubConfiguration -DisableTelemetry -SessionOnly
}

# set the GITHUB_TOKEN environment variable to the value of the GitHubToken parameter
if (![String]::IsNullOrWhiteSpace($GitHubToken)) {
    $env:GITHUB_TOKEN = $GitHubToken
}

#check if GITHUB_TOKEN is set
if ($null -eq $env:GITHUB_TOKEN) {
    Set-ActionFailed -Message "GITHUB_TOKEN is not set"
}
else {
    Write-ActionDebug "GITHUB_TOKEN is set"
}

# Allows you to specify your access token as a plain-text string ("<Your Access Token>")
# which will be securely stored on the machine for use in all future PowerShell sessions.
$secureString = ($env:GITHUB_TOKEN | ConvertTo-SecureString -AsPlainText -Force)
$cred = New-Object System.Management.Automation.PSCredential "username is ignored", $secureString
Set-GitHubAuthentication -Credential $cred
$secureString = $cred = $null # clear this out now that it's no longer needed

#Init Owner/Repo/PR variables+
$actionRepo = Get-ActionRepo
$OrganizationName = $actionRepo.Owner
$RepositoryName = $actionRepo.Repo

#Get the list of OPEN Dependabot alerts from github repo (paginated via -ExtendedResult)
#https://docs.github.com/en/rest/dependabot/alerts?apiVersion=2022-11-28#list-dependabot-alerts-for-a-repository
$perPage = 100
$Dependabot_Alerts = Invoke-GHRestMethod -Method GET -Uri "https://api.github.com/repos/$OrganizationName/$RepositoryName/dependabot/alerts?state=open&per_page=$perPage" -ExtendedResult $true
$Dependabot_Alerts_CVEs = $Dependabot_Alerts.result | % { $_.security_advisory.cve_id }
#Get next page of dependabot alerts if there is one
while ($null -ne $Dependabot_Alerts.nextLink) {
    $Dependabot_Alerts = Invoke-GHRestMethod -Method GET -Uri $Dependabot_Alerts.nextLink -ExtendedResult $true
    $Dependabot_Alerts_CVEs += $Dependabot_Alerts.result | % { $_.security_advisory.cve_id }
}

Write-ActionInfo "$OrganizationName/$RepositoryName Dependabot CVEs Count: $($Dependabot_Alerts_CVEs.Count)"
Write-ActionDebug "$OrganizationName/$RepositoryName Dependabot CVEs: $Dependabot_Alerts_CVEs"

#Grab the EPSS data(https://www.first.org/epss/data_stats) from csv https://epss.cyentia.com/epss_scores-2024-03-02.csv"
#TODO - Use First API ? https://www.first.org/epss/api
$date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd")
$csv = "epss_scores-$date.csv"
try {
    Invoke-WebRequest -Uri "https://epss.cyentia.com/$csv.gz" -OutFile "$csv.gz"
}
catch {
    # Incase the date math is delayed and the file is not available yet (TODO cache the last known good file and use that if the current date is not available yet)
    $date = (Get-Date).ToUniversalTime().AddDays(-1).ToString("yyyy-MM-dd")
    $csv = "epss_scores-$date.csv"
    Invoke-WebRequest -Uri "https://epss.cyentia.com/$csv.gz" -OutFile "$csv.gz"
}
Decompress-GZip "$csv.gz" $csv
$epss = Import-Csv -Path $csv
$epssHash = @{}
$epss | ForEach-Object { $epssHash[$_.cve] = $_ }

#Check if any Dependabot alerts have an EPSS score equal/above the threshold
$epssMatch = $Dependabot_Alerts_CVEs | ForEach-Object { $epssHash[$_] } | Where-Object { [decimal]$_.epss -ge [decimal]$EPSS_Threshold }
$isFail = $epssMatch.Count -gt 0

#Summary
$summary = "[$OrganizationName/$RepositoryName] - $($Dependabot_Alerts_CVEs.Count) Dependabot Alerts total.`n"
$summary += $isFail ? "$($epssMatch.Count) CVEs found in Dependabot alerts that exceed the EPSS '$EPSS_Threshold' threshold :`n $( $epssMatch | ForEach-Object { "$($_.cve) - $($_.epss) EPSS ($($_.percentile) percentile) `n" })" : "No CVEs found in Dependabot alerts that exceed the EPSS '$EPSS_Threshold' threshold."

if ($isFail) {
    Set-ActionFailed -Message $summary
}
else {
    Write-ActionInfo $summary
    exit 0
}
