# Shadow AI Endpoint Scanner

Endpoint-local discovery of AI tools, assistants, agents, SDKs, browser
extensions, local model runtimes, AI credentials, and active AI network sessions.
Built for Shadow AI / unsanctioned-AI inventory in regulated environments.

It answers one question for a single device: **what AI is present and in use on
this endpoint, and how exposed are we because of it.**

> **New to the command line?** See the plain-language
> [Windows setup guide](docs/SETUP-GUIDE-WINDOWS.md). A
> [sample HTML report](sample-report/shadowai-sample-report.html) is included.

## What this is, and what it is not

This is an **agent that runs on the device being assessed**. It inspects the
local machine and produces a structured inventory plus a risk-scored report. It
is **not** a remote scanner that reaches across the network to machines you do
not control. Fleet coverage comes from deploying this agent to each endpoint.

Run only on devices you are authorized to scan.

## Requirements

- **Python 3.8 or newer**
- **psutil** (the only dependency; the scanner still runs without it, but the
  process, port, and network collectors are disabled)

### Step 1 - Install Python (skip if you already have it)

Check whether Python is already installed:

```bash
python --version      # Windows
python3 --version     # macOS / Linux
```

If you see a version number (3.8 or newer), you are set. If not, download the
installer from https://www.python.org/downloads/ . **On Windows, tick "Add
Python to PATH" on the first screen of the installer.**

> On Windows the command is usually `python`; on macOS and Linux it is
> `python3`. Use whichever one prints a version on your machine.

### Step 2 - Get the scanner

Download or clone this repository so that `shadowai.py` and `signatures.json`
sit together in the same folder.

### Step 3 - Install the dependency

```bash
pip install -r requirements.txt        # Windows
pip3 install -r requirements.txt       # macOS / Linux
```

## Running a scan

```bash
python shadowai.py                      # Windows
python3 shadowai.py                     # macOS / Linux
```

This runs a full scan and writes a timestamped JSON and HTML report into a
`reports/` folder next to the script.

### Common options

```bash
python shadowai.py --no-network              # skip DNS / connection checks
python shadowai.py --output-dir C:\\logs      # choose where reports are written
python shadowai.py --json-only               # write JSON only, no HTML
python shadowai.py --signatures custom.json  # use a custom signature set
python shadowai.py --quiet                   # no console output (scheduled runs)
```

> `signatures.json` must sit next to `shadowai.py`, or be passed with
> `--signatures`. Without it the scanner stops with a configuration error
> (exit code 2).

## Reading the report

Each run produces two files in the output folder:

- **HTML** - open it in any browser. Start at the **posture banner** at the top
  (for example *critical exposure*), then read the findings grouped by severity.
  Each card shows the tool, vendor, evidence, a governance note, and why its
  severity was escalated.
- **JSON** - the same data in machine-readable form for a GRC platform, SIEM, or
  spreadsheet.

### Exit codes (for MDM / CI gating)

| Code | Meaning |
|------|---------|
| 0 | Clean, or low / medium findings only |
| 1 | At least one high finding |
| 3 | At least one critical finding |
| 2 | Configuration error (signatures.json not found) |

## Customizing detections and allowlisting

The detection knowledge base lives in `signatures.json`. To mark a sanctioned
tool, add its exact finding name to the `allowlist` array. It then stays in the
inventory at `info` severity and stops driving the posture banner and exit
codes:

```json
"allowlist": ["Microsoft Copilot", "Grammarly"]
```

## Deployment to a fleet

This agent must run in each user context to see that user's browser extensions,
environment credentials, and per-user config. Common options: push `shadowai.py`
and `signatures.json` via MDM / RMM (Intune, Jamf, Kandji, Tanium, NinjaOne) on a
schedule; run it through EDR live-response or an osquery extension; or use a
per-user scheduled task that writes JSON to a collected path. Aggregate the
per-host JSON centrally for a fleet-wide inventory and trend over time.

## License

MIT. See [LICENSE](LICENSE).
