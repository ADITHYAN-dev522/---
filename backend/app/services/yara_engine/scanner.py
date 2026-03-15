"""
YARA Engine - Real static analysis scanner.

On first startup, downloads Neo23x0/signature-base (1000+ community rules)
from GitHub into rules/signature-base/. Subsequent runs do a git pull to
keep rules fresh. All community .yar files are compiled together with the
six hardcoded built-in rules.

Falls back gracefully if yara-python is not installed or git/internet is
unavailable - built-in rules still work in that case.
"""

import hashlib
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
RULES_DIR = BASE_DIR / "rules"
RULES_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Built-in rules (always available, no network needed)
# ---------------------------------------------------------------------------
BUILTIN_RULES = r"""
rule Eicar_Test_File {
    meta:
        description = "EICAR AV test file"
        severity = "low"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PowerShell {
    meta:
        description = "Obfuscated PowerShell invocation"
        severity = "high"
    strings:
        $enc = "-EncodedCommand" nocase
        $byp = "ExecutionPolicy Bypass" nocase
        $dl  = "DownloadString" nocase
        $iex = "IEX" nocase
    condition:
        2 of them
}

rule Reverse_Shell_Bash {
    meta:
        description = "Potential bash reverse shell"
        severity = "critical"
    strings:
        $rs1 = "bash -i" nocase
        $rs2 = "/dev/tcp/" nocase
    condition:
        any of them
}

rule Hardcoded_Credential {
    meta:
        description = "Possible hardcoded credentials in source file"
        severity = "medium"
    strings:
        $p1 = "password=" nocase
        $p2 = "passwd=" nocase
        $p3 = "secret_key=" nocase
        $p4 = "api_key=" nocase
    condition:
        any of them
}

rule Base64_Shellcode {
    meta:
        description = "Large base64 blob typical of encoded shellcode"
        severity = "medium"
    strings:
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/
    condition:
        $b64
}

rule Mime_Executable_In_Script {
    meta:
        description = "ELF or PE magic bytes embedded inside a file"
        severity = "high"
    strings:
        $elf = { 7F 45 4C 46 }
        $pe  = { 4D 5A }
    condition:
        $elf or $pe
}
"""

# ---------------------------------------------------------------------------
# Community rule sources
# Each tuple: (git_clone_url, yar_subfolder_inside_repo, local_dir_name)
# ---------------------------------------------------------------------------
COMMUNITY_SOURCES = [
    (
        "https://github.com/Neo23x0/signature-base.git",
        "yara",           # only the yara/ subfolder contains .yar files
        "signature-base",
    ),
]


def _download_community_rules() -> None:
    """
    Clone each community repo on first run; run git pull on subsequent runs.
    Errors are logged as warnings only - the engine still works without them.
    """
    try:
        import git  # gitpython
    except ImportError:
        logger.warning(
            "gitpython is not installed - community YARA rules will not be "
            "downloaded. Install with: pip install gitpython"
        )
        return

    for repo_url, subdir, clone_name in COMMUNITY_SOURCES:
        clone_path = RULES_DIR / clone_name
        try:
            if clone_path.exists():
                logger.info("Pulling latest community rules: %s", clone_name)
                repo = git.Repo(clone_path)
                repo.remotes.origin.pull(depth=1)
            else:
                logger.info("Cloning community rules: %s", repo_url)
                git.Repo.clone_from(repo_url, clone_path, depth=1)

            search = (clone_path / subdir) if subdir else clone_path
            count = len(list(search.rglob("*.yar"))) if search.exists() else 0
            logger.info("[YARA] %s: %d rule files ready", clone_name, count)
        except Exception as exc:
            logger.warning(
                "Could not fetch community rules for %s: %s - continuing with built-ins",
                clone_name, exc,
            )


def _load_rules():
    """
    Import yara-python, download community rules, compile everything.
    Returns compiled yara.Rules or None if yara-python is missing.
    """
    try:
        import yara  # type: ignore
    except ImportError:
        logger.warning(
            "yara-python not installed - YARA scanning disabled. "
            "Install with: pip install yara-python"
        )
        return None

    _download_community_rules()

    # Build namespace -> source mapping for yara.compile(sources=...)
    sources: dict[str, str] = {"__builtin__": BUILTIN_RULES}

    for _, subdir, clone_name in COMMUNITY_SOURCES:
        clone_path = RULES_DIR / clone_name
        search_root = (clone_path / subdir) if subdir else clone_path
        if not search_root.exists():
            continue
        for yar_file in sorted(search_root.rglob("*.yar")):
            # Namespace = filename without extension (underscores for safety)
            ns = yar_file.stem.replace("-", "_").replace(".", "_").replace(" ", "_")
            # Avoid collisions by prefixing with parent folder name
            ns = f"{clone_name.replace('-','_')}__{ns}"
            try:
                sources[ns] = yar_file.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass

    total = len(sources)
    logger.info("[YARA] Compiling %d rule source(s)...", total)

    try:
        rules = yara.compile(
            sources=sources,
            externals={'filepath': '', 'filename': '', 'extension': ''}
        )
        logger.info("[YARA] Compilation successful (%d namespaces).", total)
        return rules
    except Exception as exc:
        logger.error(
            "[YARA] Compilation failed with community rules: %s - "
            "retrying with built-ins only.", exc
        )
        try:
            rules = yara.compile(
                source=BUILTIN_RULES,
                externals={'filepath': '', 'filename': '', 'extension': ''}
            )
            logger.info("[YARA] Built-in rules compiled successfully.")
            return rules
        except Exception as exc2:
            logger.error("[YARA] Built-in rule compile also failed: %s", exc2)
            return None


# Module-level compiled rules - loaded once at import time
_RULES = _load_rules()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_file(filepath: str) -> dict:
    """
    Scan a single file with YARA rules.
    Returns a dict with keys: file, sha256, sha1, md5, matches, error, scanned_at.
    """
    result: dict = {
        "file": filepath,
        "sha256": None,
        "sha1": None,
        "md5": None,
        "matches": [],
        "error": None,
        "scanned_at": datetime.utcnow().isoformat(),
    }

    path = Path(filepath)
    if not path.exists() or not path.is_file():
        result["error"] = "File not found"
        return result

    # Hash fingerprinting
    try:
        data = path.read_bytes()
        result["md5"]    = hashlib.md5(data).hexdigest()
        result["sha1"]   = hashlib.sha1(data).hexdigest()
        result["sha256"] = hashlib.sha256(data).hexdigest()
    except Exception as exc:
        result["error"] = f"Hashing failed: {exc}"
        return result

    # YARA scan
    if _RULES is None:
        result["error"] = "yara-python not available"
        return result

    try:
        matches = _RULES.match(
            data=data,
            timeout=30,
            externals={
                'filepath': filepath,
                'filename': path.name,
                'extension': path.suffix,
            }
        )
        result["matches"] = [
            {
                "rule": m.rule,
                "namespace": m.namespace,
                "tags": list(m.tags),
                "meta": dict(m.meta),
                "strings": [
                    {
                        "identifier": s.identifier,
                        "offset": s.instances[0].offset if s.instances else 0,
                    }
                    for s in m.strings
                ],
            }
            for m in matches
        ]
    except Exception as exc:
        result["error"] = f"YARA scan error: {exc}"

    return result


def scan_directory(directory: str, extensions: list[str] | None = None) -> list[dict]:
    """
    Walk a directory recursively and scan every matching file.

    Args:
        directory:  Root path to scan.
        extensions: Optional list of extensions to include, e.g. ['.py', '.exe'].
                    None means scan all files.
    """
    results: list[dict] = []
    root = Path(directory)
    if not root.exists():
        return results

    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if extensions and p.suffix.lower() not in extensions:
            continue
        # Skip files larger than 10 MB
        try:
            if p.stat().st_size > 10 * 1024 * 1024:
                continue
        except Exception:
            continue
        results.append(scan_file(str(p)))

    return results
