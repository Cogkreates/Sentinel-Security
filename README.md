# Sentinel Security for Hermes Agent

Sentinel checks scripts **before your agent runs them**. When Hermes is about to execute a script through the terminal or `execute_code` tools, Sentinel scans it first and then lets it run, sends it to Hermes's approval gate, or blocks it.

## What it does

| Part | How it works |
|---|---|
| **Pre-run guard** (`pre_tool_call` hook) | Finds script files in the command (`.py .ps1 .bat .cmd .sh .js .vbs`) and scans them. Clean: runs. Suspicious: sent to Hermes's human approval gate. Clearly malicious: blocked, and the model is told why. |
| `analyze_file` tool | SHA-256 of a file plus a static scan, and a VirusTotal hash lookup when a `VT_API_KEY` is configured. |
| `scan_script` tool | Static scan for network calls, credential/wallet access, dynamic code execution, persistence, bulk deletion, env-var reads. |
| Audit log | Every guarded call is appended to `sentinel-audit.jsonl` in the Hermes home folder. |

**Verdict rules:** credential access combined with network calls, or a high total score, is blocked. A moderate score goes to approval. Everything else is allowed.

## Install

1. Put this folder in your Hermes plugins directory (on Windows: `C:\Users\<you>\AppData\Local\hermes\plugins\sentinel-security`).
2. `hermes plugins enable sentinel-security`
3. Restart `hermes` and run `/plugins` to confirm it is loaded.

Set `SENTINEL_GUARD=off` to turn the guard off.

## Disclosure

- **Network:** only if a `VT_API_KEY` is configured. Then `analyze_file` and the guard send the file's **SHA-256 hash** (never the file contents) to `virustotal.com`. With no key, Sentinel makes no network calls.
- **Reads outside its own data:** it reads the script files the agent is about to run (paths found in the tool call's arguments), and `analyze_file` / `scan_script` read the path you give them.
- **Writes:** appends one JSON line per guarded call to `sentinel-audit.jsonl` in the Hermes home folder (file path, SHA-256, verdict, findings).
- **Shell commands / background processes:** none. Scripts are read, never executed.
- **Credentials:** the optional VirusTotal key is read through Hermes's secret scope. Nothing is stored by the plugin.
- **Telemetry:** none.
- **Approvals:** Sentinel only returns `block` or `approve` to Hermes's own gate. It never auto-approves or disables any guard.

## Limitations

- The scan is **static pattern matching**. Determined obfuscation can evade it. Treat it as a first line of defense, not proof of safety.
- It is **not a sandbox**. Nothing is isolated or executed.
- It inspects scripts referenced by the `terminal` tool's command and inline code passed to `execute_code`. Other routes are not covered.

## Roadmap

- Honey-data sandbox: run suspicious scripts in isolation with fake credentials and watch for exfiltration.
- Scan downloaded archives and installers.
- Per-project allow and deny lists.

## Tests

```
python test_sentinel.py
```
