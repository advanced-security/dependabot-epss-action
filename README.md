Action to detect if any open Dependabot alert CVEs exceed an EPSS threshold and fail the workflow.

![image](https://github.com/user-attachments/assets/267c2084-5769-4a82-92ae-2bad09701202)

## Usage

```yml
name: 'Dependabot EPSS Action'
on: [push]

jobs:
  dependabot-epss-action:
    name: 'EPSS Compliance Check'
    runs-on: ubuntu-latest
    steps:
      - name: 'EPSS Policy'
        uses: advanced-security/dependabot-epss-action@v0
        with:
            token: ${{ secrets.DEPENDABOT_EPSS_GITHUB_TOKEN }}
            epss-threshold: "0.6"
```

## Inputs
* [token](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token) **Required**
   * Classic Tokens
      *  repo scope or security_events scope. For public repositories, you may instead use the public_repo scope.
   * Fine-grained personal access token permissions
      * Read-Only - [Dependabot Alerts](https://docs.github.com/en/rest/overview/permissions-required-for-fine-grained-personal-access-tokens?apiVersion=2022-11-28#vulnerability-alerts)

* epss-threshold **Optional**
  * The threshold value for the Exploit Prediction Scoring System (EPSS). The EPSS is a scoring system that predicts the likelihood of a vulnerability being exploited in the wild based on a time threshold. It provides a score between 0 and 1, where 0 indicates a low likelihood of exploitation, and 1 indicates a high likelihood.The action will filter out vulnerabilities that have an EPSS score below this threshold.  See EPSS at https://www.first.org/epss. Default is `0.6`.


## Attribution
See EPSS at https://www.first.org/epss.
Jay Jacobs, Sasha Romanosky, Benjamin Edwards, Michael Roytman, Idris Adjerid, (2021), Exploit Prediction Scoring System, Digital Threats Research and Practice, 2(3)
