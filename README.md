Action to detect if any open Dependabot alert CVEs are in the list of [CISA Known Exploitable Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and fail the workflow.

![image](https://user-images.githubusercontent.com/1760475/208767910-dc8e1192-d41e-489c-bf71-ea4df20025bf.png)

```yml
name: 'Dependabot KEV Action'
on: [push]

jobs:
  dependabot-epss-action:
    name: 'CISA KEV Compliance Check'
    runs-on: ubuntu-latest
    steps:
      - name: 'KEV Policy'
        uses: advanced-security/dependabot-epss-action@v0
        env:
            GITHUB_TOKEN: ${{ secrets.DEPENDABOT_KEV_GITHUB_TOKEN }}
```

## Required Credentials
* [GITHUB_TOKEN](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token)
   * Classic Tokens
      *  repo scope or security_events scope. For public repositories, you may instead use the public_repo scope.
   * Fine-grained personal access token permissions
      * Read-Only - [Dependabot Alerts](https://docs.github.com/en/rest/overview/permissions-required-for-fine-grained-personal-access-tokens?apiVersion=2022-11-28#vulnerability-alerts)

