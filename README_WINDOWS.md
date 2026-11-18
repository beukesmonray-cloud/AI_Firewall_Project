# AI Firewall Manager for Windows

Includes install, verify, dry-run, rollback, integrity checks, and signed baseline support.

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
python .\ai_security.py
```
