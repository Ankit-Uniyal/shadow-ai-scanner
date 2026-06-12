# Shadow AI Endpoint Scanner

**Step-by-step setup and run guide for Windows.**
For any new PC and any new user. No technical background needed.

Scanner version 1.1.0 | Guide date: June 2026

---

## 1. What this tool is

This tool checks **one computer** for AI software: AI apps (like ChatGPT or Claude desktop), AI browser extensions, AI developer tools, locally running AI models, and saved AI account keys. After the check, it creates a report file you open in your web browser.

You will use it in three stages: put two files in a folder, install Python once, then type three short commands. The whole first run takes about 10 minutes. Every run after that takes under a minute.

## 2. Safety facts, in plain words

- The tool **only looks**. It does not change, delete, install, or uninstall anything on the computer.
- It **never reads passwords or secret key values**. If an AI key exists, the report only says that one exists.
- The report **stays on the computer**. Nothing is uploaded or sent anywhere.
- Only run it on computers you **own or are clearly authorized to scan** (for example your own laptop, or company devices you are responsible for).

## 3. What you need before starting

- The two scanner files: `shadowai.py` and `signatures.json` (ask the person who gave you this guide, or download them from the same place you got this document).
- An internet connection, needed once to install Python.
- About 10 minutes.

---

## 4. One-time setup (do this once per computer)

### Step 1 - Create the folder and add the two files

1. Open **File Explorer** (the yellow folder icon).
2. Open the **C: drive** (This PC, then Local Disk C:).
3. Right-click an empty area, choose **New > Folder**. Name it exactly: `shadowai`
4. Copy or move the two files into that folder, so they sit at:
   - `C:\shadowai\shadowai.py`
   - `C:\shadowai\signatures.json`

> **Important - file names must be exact.** Windows sometimes hides file endings, so a wrongly named file can look correct. In File Explorer, click the **View** menu and turn on **"File name extensions"**. Then confirm the files are named exactly `shadowai.py` and `signatures.json`. If you see `shadowai.py.py`, `shadowai.py.txt`, or `signatures.json.txt`, right-click the file, choose **Rename**, and fix it.

### Step 2 - Install Python (one time only)

1. Open your web browser and go to **https://www.python.org/downloads/**
2. Click the big yellow **Download Python** button and run the downloaded installer.
3. On the **very first installer screen**, tick the small checkbox at the bottom that says **"Add python.exe to PATH"**, then click **Install Now**.
4. Wait for **"Setup was successful"** and close the installer.

> **Important.** That checkbox is the single most important click in this whole guide. If you miss it, the commands below will fail with "python is not recognized". If that happens, simply run the installer again and tick the box.

---

## 5. Running a scan

### Step 3 - Open the command window

1. Press the **Windows key** on your keyboard.
2. Type `cmd` and press **Enter**. A black window opens. This is where you type commands.

### Step 4 - Type these three commands

Type each line into the black window and press **Enter** after each one. Wait for each to finish before typing the next.

**Command 1 of 3** - moves you into the scanner folder:

```bat
cd C:\shadowai
```

**Command 2 of 3** - installs the one helper Python needs (first time only). Lines of text will scroll, ending with "Successfully installed":

```bat
pip install psutil
```

**Command 3 of 3** - runs the scan. You will see a few "scanning..." lines, then a summary box. It takes a few seconds:

```bat
python shadowai.py
```

### Step 5 - Open the report

1. Open File Explorer and go to `C:\shadowai\reports`
2. Double-click the file ending in **.html**. The report opens in your browser.
3. The file ending in **.json** contains the same data for Excel or GRC tools. You can ignore it for normal reading.

---

## 6. How to read the report

The colored banner at the top is the **overall posture** of the computer. Findings are grouped below it by severity, most serious first. Each finding card shows what was found, the evidence, why it received its severity, and a short governance note explaining the risk in plain terms.

| Severity | What it means | What to do |
|----------|---------------|------------|
| **Critical** | An AI tool confirmed in active use, with a configured account key, or able to take actions on its own. | Review first. Decide if it is approved. If not, remove it or raise it with IT or risk. |
| **High** | A significant AI tool, extension, or saved key is present. | Confirm whether it is approved for this computer. |
| **Medium** | An AI component is present but lower urgency, often a local tool. | Record it in your inventory. No rush. |
| **Low** | A minor supporting component. | Awareness only. |
| **Info** | A tool on the approved list, or background information. | No action. It does not count toward the banner. |

> Findings on a personal laptop are normal. If you use AI tools yourself, the report will list them, and the banner may show high or critical. That means the inventory is working, not that the computer is infected.

## 7. Running it again later

Python and the helper stay installed. For every future scan, only **two** commands are needed:

```bat
cd C:\shadowai
python shadowai.py
```

Each scan creates a new, time-stamped report in the `reports` folder, so older reports are kept automatically.

## 8. Optional - mark a tool as approved

If a tool is officially approved (for example the built-in Microsoft Copilot on Windows), you can stop it from raising the alarm while keeping it in the inventory:

1. Right-click `signatures.json`, choose **Open with > Notepad**.
2. Near the top, find the line: `"allowlist": []`
3. Type the tool name between the brackets, exactly as it appears in the report, for example: `"allowlist": ["Microsoft Copilot"]`
4. Save the file (**Ctrl+S**) and run the scan again. The tool now shows as **Info** with the note "sanctioned".

## 9. If something goes wrong

| What you see | Why it happens | How to fix it |
|--------------|----------------|---------------|
| `'python' is not recognized` | The PATH checkbox was missed during the Python install. | Run the Python installer again and tick "Add python.exe to PATH". Or try: `py shadowai.py` |
| The **Microsoft Store** opens when you type `python` | Windows has a shortcut that intercepts the word python. | Use: `py shadowai.py` . If that also fails, install Python from python.org as in Step 2. |
| `can't open file 'shadowai.py'` | The file is not in the folder you are in, or its name is wrong. | Type `dir` and press Enter. Check the file is listed and named exactly `shadowai.py`. If you are in the wrong folder, type `cd C:\shadowai` |
| `signatures.json not found` | The two files are not in the same folder. | Put `shadowai.py` and `signatures.json` together in `C:\shadowai`. |
| `'pip' is not recognized` | Same PATH problem as above. | Use: `py -m pip install psutil` |
| File is named `shadowai.py.py` or ends in `.txt` | The browser or a rename added an extra ending. | In the black window type: `ren shadowai.py.py shadowai.py` (adjust to match the wrong name you see). |

## 10. Common questions

**Does it send my data anywhere?** No. Everything stays on the computer. The only internet activity during a scan is looking up the addresses of known AI services so the tool can check whether the computer is currently connected to any of them. To skip even that, run: `python shadowai.py --no-network`

**Will it slow down or change my computer?** No. It reads for a few seconds and writes two small report files.

**How do I remove it?** Delete the `C:\shadowai` folder. Python can stay for other uses, or be uninstalled from Windows Settings > Apps.

**Who should see the report?** Treat it as internal. It lists software present on a specific computer, which is useful to an attacker, so share it only with the people who need it.

---

## License

MIT. See [LICENSE](LICENSE).
