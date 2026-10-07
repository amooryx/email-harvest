<div align="center">
  <img src="./banner.svg" alt="email-harvest" width="800">
</div>

# Email Harvest

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

Collect email addresses only from sources and domains you are authorized to assess. This command-line utility supports locally generated address-format guesses, explicitly scoped HTTPS pages, public GitHub profile emails for organization members, and certificate-transparency records.

## Requirements

Python 3.9 or later. The tool uses only the Python standard library.

## Usage

Each command requires `--authorized` as an explicit confirmation that you are permitted to collect data from the named scope.

```bash
# Generate up to six common address formats per valid name (maximum 1,000 names)
python email_harvest.py guess example.com --names names.txt --authorized

# Scrape up to 25 HTTPS pages on example.com or its subdomains
python email_harvest.py scrape \
  --authorized-domain example.com \
  https://example.com/about https://www.example.com/team \
  --authorized

# Return public profile email fields for at most 25 organization members
# Optional authentication is read from the environment, never a command-line argument.
export GITHUB_TOKEN="your-token"
python email_harvest.py github example-org --limit 25 --authorized

# Search certificate-transparency results and retain only emails in this domain scope
python email_harvest.py crtsh example.com --authorized

# Save results to a JSON file instead of printing individual results
python email_harvest.py crtsh example.com --authorized --out results.json
```

PowerShell users can set the optional GitHub token with `$env:GITHUB_TOKEN = "..."`. Do not put tokens directly in commands, source files, or shared logs. An unauthenticated GitHub request is used when the variable is unset.

## Scope and safety

- The authorization flag is an acknowledgement, not a technical verification of permission. Obtain permission before running collection commands.
- Scraping is limited to HTTPS on the supplied authorized domain and its subdomains. Redirects, non-public DNS destinations, non-text content, and non-standard ports are refused.
- Requests are made serially with at least one second between requests, a ten-second timeout, and bounded response sizes. Scraping accepts at most 25 URLs. GitHub checks at most 100 member profiles (25 by default); name-guessing accepts at most 1,000 names.
- Email results are de-duplicated and restricted to the specified domain (or its subdomains). GitHub results contain only login and the public email field returned by the API.
- HTTP, DNS, parsing, and file errors are reported and cause a non-zero exit rather than being silently ignored. Results are printed or written only when you run the command; there is no database or background collection.
- These limits reduce accidental load but do not replace authorization, data-minimization, or applicable privacy requirements. This tool does not verify guessed addresses or send email.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Disclaimer

For authorized security testing only. Do not use this tool for stealth, account compromise, spam, or bulk unsolicited collection.

## Author

**Omar Khalid** — [omareldemery.com](https://omareldemery.com) | [@amooryx](https://github.com/amooryx)
