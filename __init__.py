"""Sentinel Security: a pre-execution guard for Hermes Agent.

What it does (all real, nothing simulated):
  * pre_tool_call guard: before the agent runs a script through the terminal or
    execute_code tools, Sentinel statically scans it and either lets it run,
    sends it to the human approval gate, or blocks it.
  * analyze_file tool: SHA-256 of a file plus an optional VirusTotal lookup
    (only when a VT_API_KEY secret is configured in Hermes).
  * scan_script tool: static scan of a script for suspicious behavior.

What it does NOT do: it never executes the script, and a regex scan can be
evaded by obfuscation. It is a first line of defense, not a sandbox.
"""
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

__version__ = "1.1.1"

_CTX = None
_SETTINGS = {"guard": "on"}

SCRIPT_EXTS = ("py", "ps1", "bat", "cmd", "sh", "js", "vbs")
EXEC_TOOLS = {"terminal", "execute_code"}
MAX_SCAN_BYTES = 2_000_000

# category -> (weight, description, regex)
RULES = {
    "network": (2, "Makes outbound network connections",
                r"requests\.(?:get|post|put)|urllib|http\.client|socket\.|urlopen|"
                r"Invoke-WebRequest|Invoke-RestMethod|\bcurl\b|\bwget\b"),
    "credentials": (3, "References credential, wallet or key files",
                    r"passwd|\.ssh|wallet|credential|password|\.aws|cookies|id_rsa|keychain"),
    "dynamic_exec": (2, "Decodes or dynamically executes code",
                     r"base64\.b64decode|\bexec\(|\beval\(|FromBase64String|-EncodedCommand|marshal\.loads"),
    "subprocess": (1, "Spawns system processes",
                   r"subprocess|os\.system|Popen|Start-Process|cmd\.exe"),
    "persistence": (3, "Touches startup or persistence mechanisms",
                    r"winreg|CurrentVersion\\+Run|schtasks|crontab|Startup\\+|RunOnce"),
    "destructive": (2, "Deletes files in bulk",
                    r"shutil\.rmtree|rm\s+-rf|Remove-Item\s+-Recurse|del\s+/[fsq]"),
    "env": (1, "Reads environment variables (possible token theft)",
            r"os\.environ|getenv|\$env:"),
}
_COMPILED = {k: (w, d, re.compile(p, re.I)) for k, (w, d, p) in RULES.items()}

_EXT = "|".join(SCRIPT_EXTS)
_PATH_RE = re.compile(
    r'''(?:"([^"]+?\.(?:%s))"|'([^']+?\.(?:%s))'|([^\s"'|&;<>]+?\.(?:%s)))(?=$|[\s"'|&;<>])'''
    % (_EXT, _EXT, _EXT),
    re.I,
)


# ---------------------------------------------------------------- scanning

def scan_text(text: str) -> Dict[str, str]:
    """Return {category: description} for every rule that matches."""
    return {cat: desc for cat, (_, desc, rx) in _COMPILED.items() if rx.search(text)}


def verdict_for(categories) -> tuple:
    """Map matched categories to ('allow' | 'approve' | 'block', score)."""
    cats = set(categories)
    score = sum(RULES[c][0] for c in cats)
    if {"credentials", "network"} <= cats or score >= 6:
        return "block", score
    if score >= 2:
        return "approve", score
    return "allow", score


def scan_file(path: str) -> Dict[str, Any]:
    p = Path(os.path.expanduser(path))
    sha, head = hashlib.sha256(), b""
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha.update(chunk)
            if len(head) < MAX_SCAN_BYTES:
                head += chunk[: MAX_SCAN_BYTES - len(head)]
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = head.decode("utf-16", "ignore")
    else:
        text = head.decode("utf-8", "ignore")
    found = scan_text(text)
    verdict, score = verdict_for(found)
    return {"path": str(p), "name": p.name, "sha256": sha.hexdigest(),
            "categories": list(found), "findings": list(found.values()),
            "score": score, "verdict": verdict}


def _secret(name: str) -> str:
    """Read a secret through Hermes (profile-aware), never from os.environ directly."""
    try:
        from agent.secret_scope import get_secret
        return (get_secret(name) or "").strip()
    except Exception:
        return ""


def vt_lookup(sha256: str, timeout: float = 8.0) -> Dict[str, Any]:
    """Real VirusTotal lookup. Returns status no_key / not_found / live / error."""
    key = _secret("VT_API_KEY")
    if not key:
        return {"status": "no_key", "malicious": None, "total": None}
    req = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            stats = json.load(r)["data"]["attributes"]["last_analysis_stats"]
        return {"status": "live", "malicious": stats.get("malicious", 0), "total": sum(stats.values())}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "not_found", "malicious": 0, "total": 0}
        return {"status": "error", "malicious": None, "total": None, "detail": f"HTTP {e.code}"}
    except Exception as e:  # network down, bad JSON, timeout
        return {"status": "error", "malicious": None, "total": None, "detail": str(e)}


def _vt_line(vt: Dict[str, Any]) -> str:
    s = vt["status"]
    if s == "live":
        return f"VirusTotal: {vt['malicious']}/{vt['total']} engines flagged this file"
    if s == "not_found":
        return "VirusTotal: hash not known (new or unique file)"
    if s == "no_key":
        return "VirusTotal: not checked (set VT_API_KEY to enable)"
    return f"VirusTotal: lookup failed ({vt.get('detail', 'unknown error')})"


def format_report(scan: Dict[str, Any], vt: Optional[Dict[str, Any]] = None) -> str:
    lines = [f"SENTINEL REPORT: {scan['name']}", f"SHA-256: {scan['sha256']}"]
    if vt is not None:
        lines.append(_vt_line(vt))
    if scan["findings"]:
        lines.append("Suspicious patterns:")
        lines += [f"  - {f}" for f in scan["findings"]]
    else:
        lines.append("No suspicious patterns found (this is not proof the file is safe).")
    lines.append(f"Verdict: {scan['verdict'].upper()} (score {scan['score']}). The file was not executed.")
    return "\n".join(lines)


# ------------------------------------------------------------------- guard

def _audit_dir() -> Optional[Path]:
    """This plugin's data folder inside the active Hermes home (profile-aware)."""
    try:
        from hermes_constants import get_hermes_home
        d = Path(get_hermes_home()) / "plugin-data" / "sentinel-security"
        d.mkdir(parents=True, exist_ok=True)
        return d
    except Exception:
        return None


def _guard_enabled() -> bool:
    """Guard on/off comes from the plugin setting (config.yaml), default on."""
    value = _SETTINGS.get("guard", "on")
    try:
        if _CTX is not None:
            value = _CTX.get_config("guard", default=value)
            _SETTINGS["guard"] = value
    except Exception:
        pass
    return str(value).strip().lower() != "off"


def _audit(event: Dict[str, Any]) -> None:
    try:
        d = _audit_dir()
        if d is None:
            return
        with open(d / "sentinel-audit.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%S"), **event}) + "\n")
    except Exception:
        pass


def _strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v)


def find_script_paths(args: Dict[str, Any], limit: int = 5) -> List[Path]:
    """Existing script files referenced anywhere in a tool call's arguments."""
    base = Path(str(args.get("workdir") or args.get("cwd") or os.getcwd()))
    seen, out = set(), []
    for text in _strings(args):
        for m in _PATH_RE.finditer(text):
            raw = next(g for g in m.groups() if g)
            p = Path(os.path.expanduser(raw))
            if not p.is_absolute():
                p = base / p
            try:
                if p.is_file() and str(p) not in seen:
                    seen.add(str(p))
                    out.append(p)
            except OSError:
                continue
            if len(out) >= limit:
                return out
    return out


_ORDER = {"allow": 0, "approve": 1, "block": 2}


def _decide(tool_name: str, args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    scans = []
    for p in find_script_paths(args):
        scans.append(scan_file(str(p)))
    if tool_name == "execute_code" and isinstance(args.get("code"), str):
        found = scan_text(args["code"])
        v, s = verdict_for(found)
        # Hash the code itself so an "always allow" answer covers only this exact snippet.
        scans.append({"path": "<inline code>", "name": "inline code", "inline": True,
                      "sha256": hashlib.sha256(args["code"].encode("utf-8", "ignore")).hexdigest(),
                      "categories": list(found), "findings": list(found.values()),
                      "score": s, "verdict": v})
    if not scans:
        return None

    # Real VirusTotal check (only when a key is set); a hit overrides the static verdict.
    if _secret("VT_API_KEY"):
        for sc in scans:
            if not sc.get("inline"):
                vt = vt_lookup(sc["sha256"], timeout=5.0)
                if vt["status"] == "live" and vt["malicious"]:
                    sc["verdict"] = "block"
                    sc["findings"].append(f"VirusTotal: {vt['malicious']}/{vt['total']} engines flagged it")

    worst = max(scans, key=lambda s: _ORDER[s["verdict"]])
    for sc in scans:
        _audit({"tool": tool_name, "file": sc["path"], "sha256": sc["sha256"],
                "verdict": sc["verdict"], "findings": sc["findings"]})
    if worst["verdict"] == "allow":
        return None
    detail = "; ".join(worst["findings"])
    if worst["verdict"] == "block":
        return {"action": "block", "message": (
            f"Sentinel blocked this call: {worst['name']} looks malicious ({detail}). "
            "Do not run it by another route. Tell the user and let them review the file.")}
    return {"action": "approve", "rule_key": f"sentinel:{worst['sha256'][:12]}", "message": (
        f"Sentinel flagged {worst['name']}: {detail}. Approve only if you trust this script.")}


def _pre_tool_call(tool_name=None, args=None, task_id=None, **kwargs):
    try:
        if not _guard_enabled():
            return None
        if tool_name not in EXEC_TOOLS or not isinstance(args, dict):
            return None
        return _decide(tool_name, args)
    except Exception as e:
        # Fail toward the human gate rather than silently allowing.
        return {"action": "approve",
                "message": f"Sentinel could not scan this call ({e}). Review it manually."}


# ------------------------------------------------------------------- tools

ANALYZE_SCHEMA = {
    "name": "analyze_file",
    "description": "Hash a local file, check the hash on VirusTotal (if configured) and scan it for suspicious patterns. Never executes the file.",
    "parameters": {"type": "object",
                   "properties": {"file_path": {"type": "string", "description": "Local path of the file to analyze."}},
                   "required": ["file_path"]},
}

SCAN_SCHEMA = {
    "name": "scan_script",
    "description": "Statically scan a script for suspicious behavior (network, credential access, obfuscation, persistence). Never executes the script.",
    "parameters": {"type": "object",
                   "properties": {"script_path": {"type": "string", "description": "Local path of the script to scan."}},
                   "required": ["script_path"]},
}


def _run_tool(path: Any, with_vt: bool) -> str:
    try:
        if not isinstance(path, str) or not path:
            return json.dumps({"error": "A file path is required."})
        if not os.path.isfile(os.path.expanduser(path)):
            return json.dumps({"error": f"File not found: {path}"})
        scan = scan_file(path)
        vt = vt_lookup(scan["sha256"]) if with_vt else None
        if vt and vt["status"] == "live" and vt["malicious"]:
            scan["verdict"] = "block"
        return json.dumps({"verdict": scan["verdict"], "sha256": scan["sha256"],
                           "report": format_report(scan, vt)})
    except Exception as e:
        return json.dumps({"error": f"Sentinel could not read the file: {e}"})


def _handle_analyze(args, **kwargs):
    return _run_tool((args or {}).get("file_path"), with_vt=True)


def _handle_scan(args, **kwargs):
    return _run_tool((args or {}).get("script_path"), with_vt=False)


def register(ctx):
    global _CTX
    _CTX = ctx
    try:
        _SETTINGS["guard"] = ctx.get_config("guard", default="on")
    except Exception:
        pass
    ctx.register_tool(name="analyze_file", toolset="sentinel", schema=ANALYZE_SCHEMA, handler=_handle_analyze)
    ctx.register_tool(name="scan_script", toolset="sentinel", schema=SCAN_SCHEMA, handler=_handle_scan)
    ctx.register_hook("pre_tool_call", _pre_tool_call)
