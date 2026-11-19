# AI Firewall Manager for Windows

The Windows installer enables Windows Defender Firewall for Domain, Private, and Public profiles, sets default inbound action to Block and outbound action to Allow, enables dropped-connection logging and Filtering Platform Connection success auditing, and preserves existing rules. It saves the previous profile, logging, and audit settings so the uninstaller can restore them.

The elevated monitor reads new Windows Security event 5156 records and asks the configured Ollama model to score each eligible outbound connection. A score of 90 or higher creates a temporary Block rule scoped to the verified executable, public destination IP, destination port, and TCP/UDP protocol. A scheduled task removes each rule after 24 hours. Inbound traffic, private/reserved destinations, unsupported protocols, unverified executables, and core Windows processes are never automatically blocked.

## Install or restore firewall profile settings

Open PowerShell as Administrator in the project folder and run:

```powershell
.\install_windows.ps1
```

The installer saves the previous firewall profile settings and the connection-audit policy under `C:\ProgramData\AI_Firewall_Project`. To start monitoring after installation, run:

```powershell
.\start_ai_firewall.ps1
```

The monitor starts from the latest Security event and does not replay older events. Keep the elevated PowerShell window open while it runs; press Ctrl+C to stop it. AI rules are created only for new qualifying events while the monitor is running.

To restore the previous profile, logging, and audit settings and remove AI Firewall Project rules, stop the monitor and run:

```powershell
.\uninstall_windows.ps1
```

Existing firewall rules are preserved. The monitor stores its event cursor in `%LOCALAPPDATA%\AI_Firewall_Project\wfp-event-cursor.json`.

## Local Ollama model settings

The local-risk classifier supports these environment variables:

- `OLLAMA_URL` - Ollama generate endpoint. Default: `http://127.0.0.1:11434/api/generate`
- `OLLAMA_MODEL` - Ollama model name. Default: `llama3.2:1b`
- `OLLAMA_TIMEOUT` - Request timeout in seconds. Default: `30`
- `OLLAMA_TEMPERATURE` - Model sampling temperature. Default: `0`

PowerShell example:

```powershell
$env:OLLAMA_MODEL = "llama3.2:1b"
$env:OLLAMA_TIMEOUT = "30"
$env:OLLAMA_TEMPERATURE = "0"
.\start_ai_firewall.ps1
```
