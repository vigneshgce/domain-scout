---
name: domain-scout
description: Find brandable domain names for a product, startup, app, or business idea, or check specific domains for availability and pricing. Saves a naming brief, generates candidates, checks DNS/RDAP/whois, and reports registrar prices and confirmation links.
---

# Domain Scout

Use this workflow in Codex, Pi, or Claude Code with the agent's available shell, file, search, and browser tools. Python 3.8+ is required; the checker uses only the standard library. Network access is required for live results; `whois`, browser tools, and Porkbun credentials are optional.

Resolve `scripts/check_domains.py` and [references/naming-guide.md](references/naming-guide.md) relative to this `SKILL.md`. Run the script by its absolute path **from the user's working directory**. Save briefs and reports there, never inside the installed skill. No agent-specific tool names or MCP servers are required.

## 1. Capture or reuse the brief

For a request to check supplied names/domains, go directly to step 3 with those inputs. Do not require a product brief or generate replacements unless requested.

For naming requests, read any existing `domain-brief.md` first and combine it with the conversation. Ask only for missing information essential to choosing names, especially what the product does. If direction is unspecified, use a varied batch and state that assumption. Save or update the brief without overwriting unrelated content:

```text
Product:          What it does and for whom
Naming direction: User preference, or varied brandable names
Must evoke:       2–4 qualities
Avoid:            Words, themes, competitor names
Constraints:      Ideally <=8 letters, <=10 max; pronounceable; no digits/hyphens
TLD preference:   .ai > .com > .dev, unless the user specifies otherwise
Budget:           User's maximum and currency; unspecified means no price filter
Collisions:       Known companies or tools to avoid
```

The user's choices override these defaults. Reuse the brief across batches; do not re-ask answered questions.

## 2. Generate candidates

Read the naming guide. Generate about 20 names internally and retain the best 10 across several naming styles. Explain each finalist's connection to the brief. Check availability before presenting names as viable picks.

## 3. Check availability and prices

Replace the placeholder below with the actual installed script path. Use the brief's TLD order and shell-quote arguments.

```bash
python3 /absolute/path/to/domain-scout/scripts/check_domains.py name1 name2 name3 \
  --tlds ai,com,dev --md domain-report.md --json domain-report.json
```

Bare names are checked across every requested TLD; full domains such as `example.com` check only that domain. `--file names.txt` accepts one name per line. Keep the default four workers and delay for normal batches.

The script uses DNS-over-HTTPS NS records to identify registered domains, then registry RDAP discovered through IANA, and finally the optional `whois` CLI when RDAP is inconclusive. DNS absence alone never establishes availability. Porkbun's public TLD list prices need no API key.

- `FREE`: evidence of no registration; purchasability and premium pricing remain unconfirmed.
- `FREE*`: registrar identified a premium name.
- `taken`: registered or unavailable at the checked registrar.
- `?`: inconclusive; never describe it as available.

List prices are estimates for a TLD, not quotes for that name. If both `PORKBUN_API_KEY` and `PORKBUN_SECRET_API_KEY` are already available, add `--exact` to check up to 10 free domains, or set `--max-exact` for a specific shortlist. Exact checks are rate limited. Never print or save credentials; do not claim confirmation when the API returns an error or inconclusive response. A connected registrar check tool may provide equivalent evidence.

For generated batches, if fewer than three candidates have the first-choice TLD free, try another batch of 10, up to **three batches total**. Reuse the brief, avoid repeated names, and preserve each batch as `domain-report-1.md`/`.json`, etc.; put the consolidated shortlist in `domain-report.md`. If network access fails broadly, stop and report the limitation instead of generating more names to retry the same outage. For supplied-domain checks, report those results directly.

## 4. Confirm finalists and unresolved results

If a browser tool exists, open the registrar links in the report for promising `?` results and the top picks. Record the observed availability, currency, registration term, premium status, renewal price if visible, URL, and check time. Preserve the script's raw JSON as evidence and put browser findings in the final Markdown report. Search-only snippets are not live checkout confirmation.

Without a browser tool, include the registrar links and label confirmation as pending. To open tabs locally, the checker supports `--open unclear` or `--open free` (up to 10 tabs); tell the user before doing so. Opening tabs does not read their contents. Do not assume Pi, Codex, or Claude has browser automation installed.

For finalists, use web search when available to check relevant company/product collisions, adapting queries to the business rather than assuming developer tools. Report notable conflicts or that collision checks could not be performed. This is not trademark clearance.

## 5. Report

Give a brief recap, a ranked table, and up to three recommendations with a one-line naming rationale and registrar links. Prefer the user's TLD order, budget, and naming fit; explain premium tradeoffs. Distinguish registry evidence from registrar-confirmed purchasability and distinguish annual list prices from the actual initial-term charge. Check current `.ai` minimum terms and renewal costs at the registrar instead of assuming an annual checkout total.

Do not pad the list if fewer than three suitable names are supported by evidence. Show unresolved checks honestly, with the next confirmation step. Checking names does not authorize registering, purchasing, transferring domains, or changing DNS.
