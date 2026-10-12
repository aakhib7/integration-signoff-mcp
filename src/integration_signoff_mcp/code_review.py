"""Static review of the merchant's integration code.

These are pattern-based checks, not a full security audit. "fail" results are
high-confidence problems; "warn" results are patterns a reviewer should confirm
by reading the code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .models import Finding

AREA = "code"

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "venv", ".venv", "env", "dist", "build", "__pycache__", ".next", "target",
    "Pods", ".gradle", "coverage", ".idea", ".vscode", "bower_components", ".tox", ".mypy_cache", ".pytest_cache",
}
CODE_EXTENSIONS = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".vue", ".svelte", ".java", ".kt", ".kts", ".swift",
    ".dart", ".go", ".rb", ".php", ".cs", ".scala", ".rs", ".html", ".erb", ".ejs", ".hbs", ".env", ".properties",
    ".yml", ".yaml", ".json", ".xml", ".ini", ".cfg", ".conf", ".toml",
}
CLIENT_EXTENSIONS = {".jsx", ".tsx", ".vue", ".svelte", ".html", ".swift", ".dart", ".kt"}
CLIENT_DIR_HINTS = ("public", "static", "frontend", "client", "components", "pages", "android", "ios", "mobile", "www")
SKIP_FILE_SUFFIXES = (".min.js", ".lock", "package-lock.json", "yarn.lock", ".map")

PLACEHOLDER = re.compile(r"(x{4,}|your|example|changeme|dummy|placeholder|<|\$\{|\{\{|redacted|\*{3,})", re.I)

SECRET_ASSIGNMENT = re.compile(
    r"""(?i)\b([a-z0-9_]*?(?:api[_-]?secret|secret[_-]?key|client[_-]?secret|webhook[_-]?secret|salt[_-]?key|"""
    r"""merchant[_-]?key|api[_-]?key|access[_-]?token|private[_-]?key))\b["']?\s*[:=]\s*["']([^"'\s]{12,})["']"""
)
SECRET_LITERALS = [
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{10,}"),
]
SECRET_NAME = re.compile(
    r"(?i)(api[_-]?secret|secret[_-]?key|client[_-]?secret|webhook[_-]?secret|salt[_-]?key|private[_-]?key)"
)
SIGNATURE_VERIFY = re.compile(
    r"(?i)(hmac|createHmac|compare_digest|timingSafeEqual|hash_equals|verify_?signature|verifySignature|"
    r"constructEvent|validateSignature|Signature\.verify|ConstantTimeCompare|MessageDigest\.isEqual)"
)
CONSTANT_TIME = re.compile(
    r"(compare_digest|timingSafeEqual|hash_equals|ConstantTimeCompare|MessageDigest\.isEqual|secure_compare|"
    r"FixedTimeEquals|constant_time_compare)"
)
PLAIN_COMPARE = re.compile(r"(?i)(signature\w*[\]'\")]*\s*(?:===?|!==?)\s*\S|(?:===?|!==?)[^;&|]{0,80}signature)")
TLS_DISABLED = [
    re.compile(r"verify\s*=\s*False"),
    re.compile(r"rejectUnauthorized\s*:\s*false"),
    re.compile(r"InsecureSkipVerify\s*:\s*true"),
    re.compile(r"CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)"),
    re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"),
    re.compile(r"(?i)trustAllCerts|TrustAllX509|ALLOW_ALL_HOSTNAME_VERIFIER|ServerCertificateValidationCallback"),
]
LOG_CALL = re.compile(r"(?i)\b(log(?:ger)?\.\w+|console\.\w+|print(?:ln|f)?|System\.out\.\w+|puts|fmt\.Print\w*|"
                      r"logging\.\w+|Log\.[dievw])\s*\(")
SENSITIVE_WORDS = re.compile(r"(?i)(card_?number|cardNumber|\bcvv\b|\bcvc\b|\bpan\b|upi_?pin|upiPin|\botp\b|"
                             r"password|api_?secret|secret_?key)")
FLOAT_MONEY = re.compile(r"(?i)\b(parseFloat|float|Double\.parseDouble|toDouble|Number)\s*\(\s*[\w.\[\]'\"]*amount")
CLIENT_AMOUNT = re.compile(
    r"""(req\.body\.amount|req\.body\[['"]amount|request\.(?:json|form|data|POST|GET)\s*(?:\.get\(|\[)\s*['"]amount|"""
    r"""params\[:amount\]|@RequestParam[^)]*amount|getParameter\(\s*"amount"\))"""
)
INSECURE_URL = re.compile(r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|example\.|www\.w3\.org|schemas\.)[^\s'\"]+")
PAYMENT_CONTEXT = re.compile(r"(?i)(pay|gateway|webhook|callback|checkout|refund|api)")
REDIRECT_TRUST = re.compile(
    r"""(?i)(req\.query|request\.args|request\.GET|params|searchParams|getQueryParameter)(?:\.get)?\W{0,4}"""
    r"""['"]?(status|payment_?status|txn_?status|code)['"]?"""
)


@dataclass
class Hit:
    file: str
    line: int
    text: str

    def short(self) -> str:
        return f"{self.file}:{self.line}  {self.text[:120]}"


def _is_client_file(path: Path) -> bool:
    if path.suffix in CLIENT_EXTENSIONS:
        return True
    lowered = [part.lower() for part in path.parts]
    return path.suffix in {".js", ".ts", ".mjs"} and any(hint in lowered for hint in CLIENT_DIR_HINTS)


def iter_files(root: Path, max_files: int, max_bytes: int):
    if root.is_file():
        yield root
        return
    count = 0
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if not path.is_file() or path.name.endswith(SKIP_FILE_SUFFIXES):
            continue
        if path.suffix not in CODE_EXTENSIONS and not path.name.startswith(".env"):
            continue
        try:
            if path.stat().st_size > max_bytes:
                continue
        except OSError:
            continue
        count += 1
        if count > max_files:
            return
        yield path


def _mask_secret(text: str) -> str:
    return re.sub(r"(['\"])([^'\"]{4})[^'\"]{4,}([^'\"]{2})(['\"])", r"\1\2****\3\4", text)


def review(path: str, profile: dict) -> list[Finding]:
    root = Path(path).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"{root} does not exist.")
    cfg = profile["code"]

    hits: dict[str, list[Hit]] = {key: [] for key in
                                  ("secrets", "client_secrets", "plain_compare", "tls", "logging",
                                   "float_money", "client_amount", "insecure_url", "redirect_trust")}
    webhook_files: list[str] = []
    verifying_webhook_files: list[str] = []
    files_with_constant_time: set[str] = set()
    scanned = 0

    for file in iter_files(root, cfg["max_files"], cfg["max_file_bytes"]):
        try:
            content = file.read_text(errors="ignore")
        except OSError:
            continue
        scanned += 1
        rel = str(file.relative_to(root)) if root.is_dir() else file.name
        is_client = _is_client_file(file.relative_to(root) if root.is_dir() else Path(file.name))
        is_config = file.suffix in {".json", ".yml", ".yaml", ".xml", ".properties", ".ini", ".cfg", ".conf",
                                    ".toml"} or file.name.startswith(".env")

        if re.search(r"(?i)webhook", content) and not is_config and not is_client:
            webhook_files.append(rel)
            if SIGNATURE_VERIFY.search(content):
                verifying_webhook_files.append(rel)
        if CONSTANT_TIME.search(content):
            files_with_constant_time.add(rel)

        for number, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            match = SECRET_ASSIGNMENT.search(line)
            if match and not PLACEHOLDER.search(match.group(2)) and not re.search(r"(?i)(env|getenv|config)",
                                                                                   match.group(2)):
                hits["secrets"].append(Hit(rel, number, _mask_secret(stripped)))
            elif any(p.search(line) for p in SECRET_LITERALS):
                hits["secrets"].append(Hit(rel, number, "(private key or live secret literal)"))
            if is_client and SECRET_NAME.search(line):
                hits["client_secrets"].append(Hit(rel, number, _mask_secret(stripped)))
            if is_config:
                continue
            if PLAIN_COMPARE.search(line) and "signature" in line.lower():
                hits["plain_compare"].append(Hit(rel, number, stripped))
            if any(p.search(line) for p in TLS_DISABLED):
                hits["tls"].append(Hit(rel, number, stripped))
            if LOG_CALL.search(line) and SENSITIVE_WORDS.search(line):
                hits["logging"].append(Hit(rel, number, stripped))
            if FLOAT_MONEY.search(line):
                hits["float_money"].append(Hit(rel, number, stripped))
            if not is_client and CLIENT_AMOUNT.search(line):
                hits["client_amount"].append(Hit(rel, number, stripped))
            if INSECURE_URL.search(line) and PAYMENT_CONTEXT.search(line):
                hits["insecure_url"].append(Hit(rel, number, stripped))
            if REDIRECT_TRUST.search(line):
                hits["redirect_trust"].append(Hit(rel, number, stripped))

    # Comparisons in files that already use a constant-time function are probably fine.
    hits["plain_compare"] = [h for h in hits["plain_compare"] if h.file not in files_with_constant_time]

    def rule(check_id, key, severity, title, fix, status_on_hit="fail", ok_detail="No matches."):
        found = hits[key]
        return Finding(
            check_id, AREA, severity, status_on_hit if found else "pass", title,
            (f"{len(found)} match(es):\n" + "\n".join(h.short() for h in found[:10])) if found else ok_detail,
            fix if found else "",
            {"matches": [h.__dict__ for h in found[:25]]},
        )

    findings = [
        Finding("C00", AREA, "info", "pass" if scanned else "warn", "Files scanned",
                f"{scanned} source and config files under {root.name}." if scanned
                else "No source files found at that path."),
        rule("C01", "secrets", "blocker", "No hard-coded secrets or keys",
             "Move secrets to environment variables or a secrets manager, and rotate any key committed to the repo."),
        rule("C02", "client_secrets", "blocker", "No secrets referenced in client-side code",
             "Signing, checksums and secret keys belong on the server only. The browser or app should receive a "
             "session or order token, never a secret."),
    ]

    if not webhook_files:
        findings.append(Finding("C03", AREA, "major", "warn", "Webhook handler verifies signatures",
                                "Could not find a webhook handler in the scanned code.",
                                "Point the review at the service that receives webhooks, or confirm where it lives."))
    else:
        unverified = [f for f in webhook_files if f not in verifying_webhook_files]
        verified_any = bool(verifying_webhook_files)
        findings.append(Finding(
            "C03", AREA, "blocker", "pass" if verified_any else "fail", "Webhook handler verifies signatures",
            (f"Signature verification found in: {', '.join(verifying_webhook_files[:5])}."
             if verified_any else f"Webhook code without signature verification: {', '.join(unverified[:5])}."),
            "" if verified_any else "Compute the HMAC of the raw body with the webhook secret and reject "
            "mismatches before processing.",
        ))

    findings += [
        rule("C04", "plain_compare", "minor", "Signatures are compared in constant time",
             "Use hmac.compare_digest (Python), crypto.timingSafeEqual (Node), hash_equals (PHP) or "
             "MessageDigest.isEqual (Java) instead of ==.", status_on_hit="warn"),
        rule("C05", "tls", "blocker", "TLS certificate verification is not disabled",
             "Remove the override; outbound calls to the gateway must verify certificates."),
        rule("C06", "logging", "blocker", "Card data, PINs and secrets are not logged",
             "Remove or mask these values in log statements.", status_on_hit="warn"),
        rule("C07", "float_money", "major", "Money is not handled as floating point",
             "Use integers in the smallest unit, or a decimal type, for amounts.", status_on_hit="warn"),
        rule("C08", "client_amount", "major", "Payment amount is set on the server",
             "Read the amount from your own order record, not from the request the browser sent.",
             status_on_hit="warn"),
        rule("C09", "insecure_url", "major", "Payment endpoints use HTTPS",
             "Use https:// for every gateway, webhook and callback URL."),
        rule("C10", "redirect_trust", "major", "Redirect parameters are not trusted for payment status",
             "On the return URL, confirm status with a server-side API call before marking an order paid.",
             status_on_hit="warn"),
    ]
    return findings
