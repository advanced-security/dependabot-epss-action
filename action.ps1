<#
.SYNOPSIS
Action to detect if any open Dependabot alerts exceed a specified EPSS (Ecosystem Package Security Score) threshold.  See EPSS at https://www.first.org/epss
.DESCRIPTION
Requirements:
- GITHUB_TOKEN env variable with repo scope or security_events scope. For public repositories, you may instead use the public_repo scope.
.EXAMPLE
PS>gh auth token # <-- Easy to grab a local auth token to test with from here!
PS>Write-Host "initializing local run! Ensure you provide a valid GITHUB_TOKEN otherwise you will get a 401!!! "
$VerbosePreference = 'SilentlyContinue'
$env:GITHUB_TOKEN = gh auth token
$env:GITHUB_REPOSITORY = 'vulna-felickz/python-dependabot-no-cve'
$env:GITHUB_REPOSITORY = 'vulna-felickz/log4shell-vulnerable-app'
$env:GITHUB_STEP_SUMMARY = $(New-Item -Name /_temp/_runner_file_commands/step_summary_a01d8a3b-1412-4059-9cf1-f7c4b54cff76 -ItemType File -Force).FullName
CLEAR GLOBAL VARIABLES!
Remove-Variable * -ErrorAction SilentlyContinue;
PS> action.ps1

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

function Convert-ToOrdinalPercentile {
    param (
        [decimal]$decimal
    )

    $percentile = [math]::Floor($decimal * 100)
    $suffix = 'th'

    switch ($percentile % 100) {
        { $_ -in 11..13 } { $suffix = 'th' }
        1 { $suffix = 'st' }
        2 { $suffix = 'nd' }
        3 { $suffix = 'rd' }
    }

    return "$percentile$suffix"
}

#⚪🟡🟠🔴
#low, medium, high, critical
function Convert-SeverityToEmoji {
    param (
        [string]$severity
    )

    switch ($severity) {
        "low" { return "⚪" }
        "medium" { return "🟡" }
        "high" { return "🟠" }
        "critical" { return "🔴" }
        default { return "⁉️" }
    }

}

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
$Dependabot_Alerts_CVEs = $Dependabot_Alerts.result
#Get next page of dependabot alerts if there is one
while ($null -ne $Dependabot_Alerts.nextLink) {
    $Dependabot_Alerts = Invoke-GHRestMethod -Method GET -Uri $Dependabot_Alerts.nextLink -ExtendedResult $true
    $Dependabot_Alerts_CVEs += $Dependabot_Alerts.result
}

$DependabotAlertCount = $Dependabot_Alerts_CVEs.Count
$DependabotAlertNullCveCount = $($Dependabot_Alerts_CVEs | Where-Object { $_.security_advisory.cve_id -eq $null } ).Count
Write-ActionInfo "$OrganizationName/$RepositoryName Dependabot Alert Count: $DependabotAlertCount ($DependabotAlertNullCveCount with no CVE)"
Write-ActionDebug "$OrganizationName/$RepositoryName Dependabot CVEs: $($Dependabot_Alerts_CVEs|ForEach-Object { $_.security_advisory.cve_id })"

# If no Dependabot alerts with CVEs found, no need to check EPSS
if ($null -eq $Dependabot_Alerts_CVEs -or $Dependabot_Alerts_CVEs.Count -eq 0 -or $DependabotAlertNullCveCount -eq $DependabotAlertCount) {
    Write-ActionInfo "No Dependabot Alerts with CVEs found."
    $epssMatch = @()
}
else {
    #Grab the EPSS data(https://www.first.org/epss/data_stats) from csv https://epss.cyentia.com/epss_scores-2024-03-02.csv.gz"
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


    $Dependabot_Alerts_CVEs | ForEach-Object {
        $epssInfo = $epssHash[$_.security_advisory.cve_id]
        $scoring = New-Object PSObject -Property @{
            cve              = $epssInfo.cve
            epss             = $epssInfo.epss
            percentile       = $epssInfo.percentile
            exceedsThreshold = ($epssInfo -and [decimal]$epssInfo.epss -ge [decimal]$EPSS_Threshold) ? $true : $false
        }
        $_ | Add-Member -MemberType NoteProperty -Name "scoring" -Value $scoring
    }
}

#set failure if an of the Dependabot_Alerts_CVEs have an EPSS score equal/above the threshold
$Failures = $Dependabot_Alerts_CVEs | Where-Object { $_.Scoring.exceedsThreshold }
$isFail = $Failures.Count -gt 0

#Summary
$summary = "[$OrganizationName/$RepositoryName] - $($Dependabot_Alerts_CVEs.Count) Dependabot Alerts total that reference a CVE.`n"
$summary += $isFail ? "Found $($Failures.Count) CVEs in Dependabot alerts that exceed the EPSS '$EPSS_Threshold' threshold :`n $( $Failures | ForEach-Object { "$($_.scoring.cve) - $($_.scoring.epss) EPSS ($($_.scoring.percentile) percentile) `n" })" : "No CVEs found in Dependabot alerts that exceed the EPSS '$EPSS_Threshold' threshold."

#Actions Markdown Summary - https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#adding-a-job-summary
#flashy! - https://github.blog/2022-05-09-supercharging-github-actions-with-job-summaries/
$markdownSummary = "# $($isFail ? '🚨' : '👍') Dependabot EPSS[^1] 🤖 Report ($((Get-Date).ToString("yyyy-MM-dd"))) `n"

if ($isFail) {

    $markdownSummary += @"
| Status 🚦 | CVE 🐛 | EPSS(Percentile) 🚨 | Dependabot 🤖 | Advisory 🔒 | CVSS 🔢 | Created 📅 | Package 📦 | Manifest 📝 | Scope 🖥️ | Fix ❓ |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | `n
"@


    #Loop through all $epssMatch and add to markdownSummary
    $markdownSummaryTableRows = $Failures | ForEach-Object {
        $cve = $_.scoring.cve
        $epss = [math]::Round([decimal]$_.scoring.epss * 100).ToString() + '%'
        $percentile = Convert-ToOrdinalPercentile -decimal $_.scoring.percentile
        $ghsa = $_.security_advisory.ghsa_id
        $created = $_.created_at.ToString("yyyy-MM-dd")
        $alertNumber = $_.number
        $alertUrl = $_.html_url
        $cvssScore = $_.security_advisory.cvss.score
        $cvssVector = $_.security_advisory.cvss.vector_string
        $package = $_.dependency.package.name
        $ecosystem = $_.dependency.package.ecosystem
        $manifest = $_.dependency.manifest_path
        $advisory = $_.security_advisory.summary
        $severity = $_.security_advisory.severity
        $color = Convert-SeverityToEmoji -severity $_.security_advisory.severity
        $scope = $_.dependency.scope
        $fixAvailable = $_.security_vulnerability.first_patched_version -and $_.security_vulnerability.first_patched_version.identifier -ne $null ? "[✅](# `"$($_.security_vulnerability.first_patched_version.identifier)`")" : "❌"
        "[🔴](## `"Error`") | [$cve](https://nvd.nist.gov/vuln/detail/$cve) | $epss ($percentile) | [#$alertNumber]($alertUrl) [🤖](## `"$advisory`") | [$ghsa](https://github.com/advisories/$ghsa) | [$color](## `"$severity`")[$cvssScore](https://www.first.org/cvss/calculator/3.1#$cvssVector) | $created | $package ($ecosystem) | [📝](## `"$manifest`") | $scope | $fixAvailable `n"
    }
    $markdownSummary += $markdownSummaryTableRows
}
else {
    $markdownSummary += $summary
}

$markdownSummary += "[^1]: The Exploit Prediction Scoring System (EPSS) is a data-driven effort for estimating the likelihood (probability) that a software vulnerability will be exploited in the wild. EPSS is a percentile score that ranges from 0 to 1, with higher scores indicating a higher likelihood of exploitation. For more information, see [FIRST.org](https://www.first.org/epss).`n"


#Output Step Summary  - To the GITHUB_STEP_SUMMARY environment file. GITHUB_STEP_SUMMARY is unique for each step in a job
$markdownSummary > $env:GITHUB_STEP_SUMMARY
#Get-Item -Path $env:GITHUB_STEP_SUMMARY | Show-Markdown
Write-ActionDebug "Markdown Summary from env var GITHUB_STEP_SUMMARY: '$env:GITHUB_STEP_SUMMARY' "
Write-ActionDebug $(Get-Content $env:GITHUB_STEP_SUMMARY)

if ($isFail) {
    Set-ActionFailed -Message $summary
}
else {
    Write-ActionInfo $summary
    exit 0
}
