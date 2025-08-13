import argparse
import httpx
import asyncio
from tqdm import tqdm
from colorama import Fore, Style, init as colorama_init
import socket
from urllib.parse import urlparse
import ssl
import smtplib
from email.message import EmailMessage
import time
from datetime import datetime, timezone
import getpass
from typing import Dict, List, Optional, Tuple
import os
import sys
import atexit
import signal
import subprocess
import shutil

# Banner (ASCII, centered)
def build_ascii_banner() -> str:
    lines = [
        "StatusChecker.py",
        "Created By: BLACK_SCORP10",
        "Telegram: @BLACK_SCORP10",
    ]
    width = max(len(s) for s in lines)
    width = max(width, 28)
    top = "=" * (width + 4)
    body = "\n".join([f"| {s.center(width)} |" for s in lines])
    bottom = "=" * (width + 4)
    return f"{top}\n{body}\n{bottom}"

# Color Codes
COLORS = {
    "1xx": Fore.WHITE,
    "2xx": Fore.GREEN,
    "3xx": Fore.YELLOW,
    "4xx": Fore.RED,
    "5xx": Fore.LIGHTRED_EX,
    "Invalid": Fore.WHITE
}

# Debug flag (set from --debug)
DEBUG = False

# Banner box (Unicode)
BANNER = """
╔═══════════════════════════════╗
║      StatusChecker.py         ║
║  Created By: BLACK_SCORP10    ║
║  Enhanced By: matteocapricci  ║
║  Revamped By: LOCS Automation ║
╚═══════════════════════════════╝
"""

# Header box per expert UI spec, with safe ASCII fallback
def print_header_box() -> None:
    lines = [
        "StatusChecker.py",
        "Created By: BLACK_SCORP10",
        "Telegram: @BLACK_SCORP10",
    ]
    pad = 2
    inner_w = max(len(s) for s in lines) + pad
    try:
        print(BANNER)
    except Exception:
        top = "=" * (inner_w + 2)
        bottom = "=" * (inner_w + 2)
        print(Style.BRIGHT + Fore.WHITE + top + Style.RESET_ALL)
        for s in lines:
            print(Style.BRIGHT + Fore.WHITE + "|" + s.center(inner_w) + "|" + Style.RESET_ALL)
        print(Style.BRIGHT + Fore.WHITE + bottom + Style.RESET_ALL)
    print()

# Function to resolve hostname to IP:Port
def resolve_ip_and_port(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        scheme = parsed.scheme
        port = parsed.port or (443 if scheme == "https" else 80)
        ip_address = socket.gethostbyname(hostname)
        return f"{ip_address}:{port}"
    except Exception:
        return "IP:Port Not Found"

# TLS certificate helper
def _get_certificate_info_sync(hostname: str, port: int) -> Optional[Dict[str, str]]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                # Not all fields always available
                issuer = None
                issuer_tuple = cert.get("issuer")
                if issuer_tuple:
                    # issuer is a tuple of tuples ((('commonName', 'XYZ'),), ...)
                    flat = dict(x for sub in issuer_tuple for x in sub)
                    issuer = flat.get("commonName") or flat.get("organizationName")

                not_after_str = cert.get("notAfter")  # e.g., 'Apr 15 12:00:00 2026 GMT'
                expires_iso = None
                days_left = None
                if not_after_str:
                    try:
                        expires_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        expires_iso = expires_dt.strftime("%Y-%m-%d %H:%M:%S %Z")
                        days_left = str((expires_dt - now).days)
                    except Exception:
                        pass
                return {
                    "issuer": issuer or "Unknown",
                    "expires_on": expires_iso or (not_after_str or "Unknown"),
                    "days_left": days_left or "Unknown",
                }
    except Exception:
        return None


async def get_certificate_info(hostname: str, port: int) -> Optional[Dict[str, str]]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _get_certificate_info_sync, hostname, port)


# Function to check URL status and redirection with optional expert details
async def check_url_status(session, url_id: int, url: str, expert: bool = False):
    original_input_url = url
    if "://" not in url:
        url = "https://" + url
    try:
        start_time = time.perf_counter()
        response = await session.get(url, follow_redirects=True, timeout=10)
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        final_url = str(response.url)

        original_ip_port = resolve_ip_and_port(url)
        redirect_ip_port = resolve_ip_and_port(final_url) if final_url != url else None

        result = {
            "url_id": url_id,
            "input_url": original_input_url,
            "checked_url": url,
            "status_code": response.status_code,
            "final_url": final_url if final_url != url else None,
            "original_ip_port": original_ip_port,
            "redirect_ip_port": redirect_ip_port,
            "elapsed_ms": elapsed_ms,
        }

        if expert:
            # Additional details for expert mode
            http_version = getattr(response, "http_version", None)
            server_header = response.headers.get("server")
            content_length = response.headers.get("content-length")
            redirect_chain = [str(r.url) for r in getattr(response, "history", [])] if hasattr(response, "history") else []

            result.update({
                "http_version": http_version,
                "server": server_header,
                "content_length": content_length,
                "redirect_chain": redirect_chain,
                "certificate": None,
            })

            parsed = urlparse(url)
            if parsed.scheme == "https" and parsed.hostname:
                cert_info = await get_certificate_info(parsed.hostname, parsed.port or 443)
                result["certificate"] = cert_info

        return result
    except httpx.RequestError:
        return {
            "url_id": url_id,
            "input_url": original_input_url,
            "checked_url": url,
            "status_code": None,
            "final_url": None,
            "original_ip_port": None,
            "redirect_ip_port": None,
            "elapsed_ms": None,
        }

# Argument parser
def parse_arguments():
    parser = argparse.ArgumentParser(description="URL Status Checker")
    parser.add_argument("-d", "--domain", help="Single domain/URL to check")
    parser.add_argument("-l", "--list", help="File containing list of domains/URLs to check")
    parser.add_argument("-o", "--output", help="File to save the output")
    parser.add_argument("-m", "--mode", choices=["beginner", "expert"], help="Output mode: beginner or expert")
    parser.add_argument("--monitor", action="store_true", help="Continuously monitor until stopped")
    parser.add_argument("--interval", type=int, default=60, help="Seconds between checks when monitoring (default: 60)")
    parser.add_argument("--notify", choices=["none", "email", "sms", "both"], help="Send notification on downtime")
    parser.add_argument("--email", help="Email address to send notifications to (and from)")
    parser.add_argument("--smtp-server", dest="smtp_server", help="SMTP server (e.g., smtp.gmail.com)")
    parser.add_argument("--smtp-port", dest="smtp_port", type=int, help="SMTP port (e.g., 587)")
    parser.add_argument("--smtp-username", dest="smtp_username", help="SMTP username (usually your email)")
    parser.add_argument("--smtp-password", dest="smtp_password", help="SMTP password or app password")
    parser.add_argument("--sms-number", dest="sms_number", help="Phone number for SMS (digits only)")
    parser.add_argument("--sms-carrier", dest="sms_carrier", choices=["att", "verizon", "tmobile", "sprint"], help="Carrier for email-to-SMS gateway")
    parser.add_argument("--prefer-mms", dest="prefer_mms", action="store_true", help="Use MMS gateway when available (helps delivery, e.g., AT&T)")
    parser.add_argument("--no-prompt", dest="no_prompt", action="store_true", help="Never prompt for passwords; use env vars or flags")
    parser.add_argument("--show-password", dest="show_password", action="store_true", help="Show SMTP password while typing (for troubleshooting)")
    parser.add_argument("--debug", action="store_true", help="Show detailed error messages (SMTP, network)")
    parser.add_argument("-v", "--version", action="store_true", help="Display version information")
    parser.add_argument("-update", action="store_true", help="Update the tool")
    return parser.parse_args()


def email_gateway_for_carrier(number: str, carrier: str, prefer_mms: bool = False) -> Optional[str]:
    if not number:
        return None
    # Default SMS gateways
    gateways = {
        "att": "@txt.att.net",
        "verizon": "@vtext.com",
        "tmobile": "@tmomail.net",
        "sprint": "@messaging.sprintpcs.com",
    }
    # Prefer MMS when requested (only implement for AT&T for now)
    if prefer_mms and carrier and carrier.lower() == "att":
        gateways["att"] = "@mms.att.net"
    domain = gateways.get(carrier.lower()) if carrier else None
    if not domain:
        return None
    digits = "".join(ch for ch in number if ch.isdigit())
    if not digits:
        return None
    return f"{digits}{domain}"


def infer_email_provider_from_address(email: str) -> str:
    """Infer common email provider from an email address.
    Returns one of: gmail, outlook, office365, yahoo, icloud, unknown
    """
    try:
        domain = email.split("@", 1)[1].lower()
    except Exception:
        return "unknown"
    if domain in ("gmail.com", "googlemail.com"):
        return "gmail"
    if domain in ("outlook.com", "hotmail.com", "live.com", "msn.com"):
        return "outlook"
    if domain in ("yahoo.com", "ymail.com", "rocketmail.com"):
        return "yahoo"
    if domain in ("icloud.com", "me.com", "mac.com"):
        return "icloud"
    # Many business/edu domains may use Office 365, but we cannot reliably infer
    return "unknown"


def smtp_settings_for_provider(provider: str) -> Tuple[str, int]:
    """Map provider label to SMTP server and port (STARTTLS)."""
    provider = (provider or "").lower()
    if provider == "gmail":
        return "smtp.gmail.com", 587
    if provider in ("outlook", "hotmail", "live", "msn"):
        return "smtp-mail.outlook.com", 587
    if provider in ("office365", "o365", "m365", "office"):
        return "smtp.office365.com", 587
    if provider == "yahoo":
        return "smtp.mail.yahoo.com", 587
    if provider == "icloud":
        return "smtp.mail.me.com", 587
    # Default to Gmail settings if unknown
    return "smtp.gmail.com", 587


# ===== In-memory session cache for secrets (never stored in args) =====
SESSION_CACHE: Dict[str, Optional[str]] = {}


def set_session_secret(name: str, value: Optional[str]) -> None:
    if value is not None:
        SESSION_CACHE[name] = value


def get_session_secret(name: str) -> Optional[str]:
    return SESSION_CACHE.get(name)


def _redact_cli_flag(flag: str) -> None:
    try:
        # redact forms: --flag value  and --flag=value
        for i, token in enumerate(list(sys.argv)):
            if token == flag and i + 1 < len(sys.argv):
                sys.argv[i + 1] = "***"
            elif token.startswith(flag + "="):
                sys.argv[i] = flag + "=***"
    except Exception:
        pass


def extract_and_redact_cli_secrets(args) -> None:
    try:
        if getattr(args, "smtp_password", None):
            set_session_secret("smtp_password", args.smtp_password)
            try:
                args.smtp_password = None
            except Exception:
                pass
            _redact_cli_flag("--smtp-password")
    except Exception:
        pass


def resolve_smtp_password(settings: Dict) -> Optional[str]:
    return get_session_secret("smtp_password") or settings.get("smtp_password")


atexit.register(lambda: SESSION_CACHE.clear())


def prompt_for_settings(args) -> Dict:
    # Output mode
    mode = args.mode
    if not mode:
        mode = input("Choose mode [B]eginner/[E]xpert (default B): ").strip().lower()
        mode = "expert" if mode.startswith("e") else "beginner"

    # Monitoring
    monitor = args.monitor
    if not monitor:
        monitor_in = input("Monitor continuously? [y/N]: ").strip().lower()
        monitor = monitor_in.startswith("y")

    interval = args.interval or 60
    if monitor and (not args.interval):
        try:
            interval = int(input("Seconds between checks (default 60): ").strip() or "60")
        except ValueError:
            interval = 60

    # Notifications
    notify = args.notify
    if not notify:
        notify_in = input("Notifications on downtime? [n]one/[e]mail/[s]ms/[b]oth (default n): ").strip().lower()
        if notify_in.startswith("e"):
            notify = "email"
        elif notify_in.startswith("s"):
            notify = "sms"
        elif notify_in.startswith("b"):
            notify = "both"
        else:
            notify = "none"

    email_addr = args.email
    smtp_server = args.smtp_server
    smtp_port = args.smtp_port
    smtp_username = args.smtp_username
    # Prefer env var for password if provided; flags are last resort
    smtp_password = os.getenv("SMTP_APP_PASSWORD") or args.smtp_password
    sms_number = args.sms_number
    sms_carrier = args.sms_carrier

    if notify in ("email", "both", "sms"):
        # Collect minimal info
        if notify in ("email", "both") and not email_addr:
            email_addr = input("Enter your email (used to send alerts): ").strip()
        if notify in ("sms", "both") and not sms_number:
            sms_number = input("Enter phone number for SMS (digits only): ").strip()
        if notify in ("sms", "both") and not sms_carrier:
            sms_carrier = input("Carrier for SMS [att/verizon/tmobile/sprint]: ").strip().lower()

        # Simplified SMTP config (we use email even for SMS via gateway)
        if notify in ("email", "both", "sms") and (not smtp_server or not smtp_port or not smtp_username or not smtp_password):
            # Username defaults to your email
            if not smtp_username:
                smtp_username = (email_addr or "").strip() or input("Enter your email (used to send alerts): ").strip()
                if not email_addr:
                    email_addr = smtp_username
            # Infer server/port from email provider; avoid asking about ports
            if not smtp_server or not smtp_port:
                provider_guess = infer_email_provider_from_address(smtp_username)
                if provider_guess == "unknown":
                    provider_choice = input("Your email provider [gmail/outlook/yahoo/icloud/office365] (default gmail): ").strip().lower()
                    if provider_choice not in ("gmail", "outlook", "yahoo", "icloud", "office365"):
                        provider_choice = "gmail"
                    smtp_server, smtp_port = smtp_settings_for_provider(provider_choice)
                else:
                    smtp_server, smtp_port = smtp_settings_for_provider(provider_guess)
            # Ask for password last, keep in session cache only (unless --no-prompt)
            cached_pw = get_session_secret("smtp_password")
            if cached_pw:
                smtp_password = cached_pw
            if not smtp_password and not getattr(args, "no_prompt", False):
                if getattr(args, "show_password", False):
                    smtp_password = input("Email password (visible): ")
                else:
                    smtp_password = getpass.getpass("Email password (use an app password if required): ")
            set_session_secret("smtp_password", smtp_password)

    return {
        "mode": mode,
        "monitor": monitor,
        "interval": interval,
        "notify": notify,
        "email": email_addr,
        "smtp_server": smtp_server,
        "smtp_port": smtp_port,
        "smtp_username": smtp_username,
        # Do not persist password in settings; keep only in-memory
        "smtp_password": None,
        "sms_number": sms_number,
        "sms_carrier": sms_carrier,
    }


def send_email_via_smtp(smtp_server: str, smtp_port: int, smtp_username: str, smtp_password: str,
                        subject: str, body: str, sender: str, recipients: List[str]) -> bool:
    try:
        if DEBUG:
            try:
                print(f"SMTP connect to {smtp_server}:{smtp_port} as {smtp_username}")
                print("Recipients:", ", ".join(recipients))
            except Exception:
                pass
        msg = EmailMessage()
        msg["From"] = sender
        msg["To"] = ", ".join(recipients)
        msg["Subject"] = subject
        msg.set_content(body)

        with smtplib.SMTP(smtp_server, smtp_port, timeout=15) as server:
            server.ehlo()
            try:
                server.starttls()
                server.ehlo()
            except Exception:
                pass
            if smtp_username and smtp_password:
                server.login(smtp_username, smtp_password)
            server.send_message(msg)
        return True
    except Exception as e:
        if DEBUG:
            try:
                print("SMTP send failed:", repr(e))
            except Exception:
                pass
        return False


# ===== PowerShell history scrubbing (best-effort) =====
def _get_ps_history_paths() -> List[str]:
    paths: List[str] = []
    appdata = os.getenv("APPDATA") or ""
    if appdata:
        # Windows PowerShell 5.1
        paths.append(os.path.join(appdata, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"))
        # PowerShell 7+
        paths.append(os.path.join(appdata, "Microsoft", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"))
    # Ask PowerShell where it actually writes history
    try:
        completed = subprocess.run([
            "powershell", "-NoProfile", "-Command", "(Get-PSReadLineOption).HistorySavePath"
        ], capture_output=True, text=True, timeout=2)
        if completed.returncode == 0:
            line = (completed.stdout or "").strip()
            if line:
                paths.insert(0, line)
    except Exception:
        pass
    # Deduplicate
    seen = set()
    unique_paths: List[str] = []
    for p in paths:
        if p and p not in seen:
            unique_paths.append(p)
            seen.add(p)
    return unique_paths


def _scrub_history_lines(lines: List[str], sensitive_tokens: List[str]) -> List[str]:
    if not sensitive_tokens:
        return lines
    filtered: List[str] = []
    for line in lines:
        try:
            if any(token and token in line for token in sensitive_tokens):
                # Skip lines containing sensitive info
                continue
        except Exception:
            pass
        filtered.append(line)
    return filtered


def scrub_powershell_history(sensitive_tokens: List[str]) -> None:
    try:
        for path in _get_ps_history_paths():
            try:
                if not path or not os.path.exists(path):
                    continue
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.read().splitlines()
                new_lines = _scrub_history_lines(lines, sensitive_tokens)
                if new_lines != lines:
                    with open(path, "w", encoding="utf-8", errors="ignore") as f:
                        f.write("\n".join(new_lines) + ("\n" if new_lines else ""))
            except Exception:
                continue
    except Exception:
        pass


def register_history_scrubber(args) -> None:
    # Only attempt scrubbing if a sensitive value is present on CLI
    tokens: List[str] = []
    try:
        if getattr(args, "smtp_password", None):
            tokens.extend(["--smtp-password", str(args.smtp_password)])
        # Also scrub common variants just in case
        if getattr(args, "smtp_username", None):
            tokens.append(str(args.smtp_username))
        if getattr(args, "email", None):
            tokens.append(str(args.email))
    except Exception:
        pass

    if not tokens:
        return

    def _cleanup():
        scrub_powershell_history(tokens)

    # Scrub at normal exit
    atexit.register(_cleanup)

    # Scrub on Ctrl+C
    try:
        original_handler = signal.getsignal(signal.SIGINT)

        def _on_sigint(sig, frame):
            try:
                _cleanup()
            finally:
                # Re-raise to default behavior
                if callable(original_handler):
                    original_handler(sig, frame)
                else:
                    raise KeyboardInterrupt

        signal.signal(signal.SIGINT, _on_sigint)
    except Exception:
        pass


def build_notification_targets(settings: Dict) -> List[str]:
    recipients: List[str] = []
    if settings["notify"] in ("email", "both") and settings.get("email"):
        recipients.append(settings["email"])
    if settings["notify"] in ("sms", "both"):
        sms_addr = email_gateway_for_carrier(
            settings.get("sms_number") or "",
            settings.get("sms_carrier") or "",
            bool(getattr(settings, "get", None) and settings.get("prefer_mms", False)) or bool(settings.get("prefer_mms", False)),
        )
        if sms_addr:
            recipients.append(sms_addr)
    return recipients

def print_beginner_view(results: Dict[int, Dict], show_spinner: bool = True) -> None:
    # Spinner not needed when progress bar is shown above; keep for fallback
    if show_spinner:
        try:
            for _ in tqdm(range(16), desc="Checking", ncols=60, ascii=True, leave=False):
                time.sleep(0.05)
        except Exception:
            pass

    # Determine simple summary: Good (green), Caution (yellow), Website Down (red)
    has_down = False
    has_warning = False
    for _, data in results.items():
        status = data.get("status_code")
        if isinstance(status, int):
            if 200 <= status < 300:
                continue
            elif 300 <= status < 400:
                has_warning = True
            else:
                has_down = True
        else:
            has_down = True

    if has_down:
        print(Fore.RED + "Website Down" + Style.RESET_ALL)
    elif has_warning:
        print(Fore.YELLOW + "Caution" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "Good" + Style.RESET_ALL)
    
    # Show per-URL simple status so multiple URLs are handled clearly
    for _, data in results.items():
        url = data.get("input_url") or data.get("checked_url")
        status = data.get("status_code") or "Invalid"
        if isinstance(status, int):
            if 200 <= status < 300:
                line_color = Fore.GREEN
                state = "UP"
            elif 300 <= status < 400:
                line_color = Fore.YELLOW
                state = "UP"
            else:
                line_color = Fore.RED
                state = "DOWN"
        else:
            line_color = Fore.RED
            state = "DOWN"
        print(line_color + f"[{state}] {url} [Status : {status}]" + Style.RESET_ALL)

def print_results(results: Dict[int, Dict], mode: str):
    status_codes: Dict[str, List[Tuple[int, Dict]]] = {
        "1xx": [],
        "2xx": [],
        "3xx": [],
        "4xx": [],
        "5xx": [],
        "Invalid": [],
    }

    # Group results
    for url_id, data in results.items():
        status = data.get("status_code")
        if status is not None:
            group = str(status)[0] + "xx"
            status_codes[group].append((url_id, data))
        else:
            status_codes["Invalid"].append((url_id, data))

    # Print with headers colored and items in specified formats
    for code, items in status_codes.items():
        if not items:
            continue
        # Header color mapping per spec
        header_color = Fore.WHITE
        if code == "2xx":
            header_color = Fore.GREEN
        elif code == "3xx":
            header_color = Fore.YELLOW
        elif code == "4xx":
            header_color = Fore.RED
        elif code == "5xx":
            header_color = Fore.LIGHTRED_EX
        elif code == "Invalid":
            header_color = Fore.RED
        else:
            header_color = Fore.WHITE
        print(header_color + f"==== {code.upper()} ====")
        for _, data in items:
            url = data.get("input_url") or data.get("checked_url")
            status = data.get("status_code") or "Invalid"
            if mode == "beginner":
                state = "UP" if isinstance(status, int) and 200 <= status < 400 else "DOWN"
                print(f"[{state}] {url} [Status : {status}]")
            else:
                # Expert line: color entire line by group
                line_color = Fore.WHITE
                if code == "2xx":
                    line_color = Fore.GREEN
                elif code == "3xx":
                    line_color = Fore.YELLOW
                elif code in ("4xx", "5xx", "Invalid"):
                    line_color = Fore.RED
                else:
                    line_color = Fore.WHITE
                print(line_color + f"[Status : {status}] = {url}" + Style.RESET_ALL)
        print(Style.RESET_ALL)


async def run_checks_once(urls: List[str], expert: bool) -> Dict[int, Dict]:
    async with httpx.AsyncClient() as session:
        tasks = [check_url_status(session, url_id, url, expert=expert) for url_id, url in enumerate(urls)]
        results: Dict[int, Dict] = {}
        for coro in asyncio.as_completed(tasks):
            data = await coro
            results[data["url_id"]] = data
        return results


def summarize_state(results: Dict[int, Dict]) -> Tuple[int, int]:
    up = 0
    down = 0
    for _, data in results.items():
        status = data.get("status_code")
        if isinstance(status, int) and 200 <= status < 400:
            up += 1
        else:
            down += 1
    return up, down


def build_down_message(url: str, data: Dict) -> str:
    status = data.get("status_code")
    checked = data.get("checked_url")
    ip = data.get("original_ip_port")
    elapsed = data.get("elapsed_ms")
    final = data.get("final_url")
    lines = [
        f"Website DOWN: {url}",
        f"Status: {status}",
        f"Checked URL: {checked}",
        f"IP: {ip}",
        f"Redirect: {final or 'None'}",
        f"Response time: {elapsed or '?'} ms",
        f"Time (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    return "\n".join(lines)


async def main():
    colorama_init(autoreset=True)
    args = parse_arguments()
    # Set debug flag
    global DEBUG
    try:
        DEBUG = bool(getattr(args, "debug", False))
    except Exception:
        DEBUG = False
    # Register best-effort PowerShell history scrubber (if user supplied sensitive CLI args)
    try:
        register_history_scrubber(args)
    except Exception:
        pass
    # Extract any CLI-provided secrets into in-memory cache and redact argv
    try:
        extract_and_redact_cli_secrets(args)
    except Exception:
        pass

    # NOTE: No hard-coded credentials. Use CLI, env vars, or interactive prompt.
    
    if args.version:
        print("StatusChecker.py version 1.1")
        return

    if args.update:
        print("Checking for updates...")  # Implement update logic here
        return

    # Expert UI header box per spec
    print_header_box()

    urls: List[str] = []

    # Prefer CLI/domain list if provided; otherwise prompt interactively
    if args.domain:
        urls.append(args.domain)
    elif args.list:
        with open(args.list, 'r') as file:
            urls.extend([line.strip() for line in file.read().splitlines() if line.strip()])
    else:
        # Ask how many URLs to monitor, then collect them
        try:
            count_raw = input("How many URLs would you like to monitor? (default 1): ").strip()
            num_urls = int(count_raw) if count_raw else 1
        except Exception:
            num_urls = 1
        if num_urls < 1:
            num_urls = 1
        for idx in range(1, num_urls + 1):
            ui = input(f"Enter URL #{idx}: ").strip()
            if ui:
                urls.append(ui)

    if not urls:
        print("No input provided. Use -d or -l option, or enter a URL.")
        return

    # Ask for mode right after URL entry if not provided
    if not args.mode:
        mode_in = input("Choose mode [B]eginner/[E]xpert (default B): ").strip().lower()
        chosen_mode = "expert" if mode_in.startswith("e") else "beginner"
        try:
            setattr(args, "mode", chosen_mode)
        except Exception:
            pass

    settings = prompt_for_settings(args)
    # Attach prefer_mms from args into settings dict for downstream functions
    try:
        if getattr(args, "prefer_mms", False):
            settings["prefer_mms"] = True
    except Exception:
        pass
    # Resolve password from in-memory cache or settings for use in SMTP send
    smtp_pw = resolve_smtp_password(settings)
    expert = settings["mode"] == "expert"

    recipients = build_notification_targets(settings)

    last_status_up: Dict[str, bool] = {}

    # Send a quick startup notification when monitoring begins
    if settings["monitor"] and settings["notify"] != "none" and recipients:
        try:
            started_subject = "Monitoring started"
            started_body = (
                f"Monitoring started for {len(urls)} URL(s): " + ", ".join(urls)
            )
            ok = send_email_via_smtp(
                settings["smtp_server"],
                settings["smtp_port"],
                settings["smtp_username"],
                smtp_pw,
                started_subject,
                started_body,
                settings.get("email") or settings.get("smtp_username") or "",
                recipients,
            )
            if ok:
                print("Startup notification sent to:", ", ".join(recipients))
            else:
                if DEBUG:
                    print("Warning: Failed to send startup notification. Check email/app password and provider settings.")
        except Exception:
            pass

    async def do_one_cycle(first_cycle: bool = False):
        nonlocal last_status_up
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        results = await run_checks_once(urls, expert=expert)
        print(f"\n[{timestamp}] Completed check for {len(urls)} URL(s)")
        if settings["mode"] == "beginner":
            print_beginner_view(results, show_spinner=False)
        else:
            print_results(results, settings["mode"])  # Grouped expert output
        # Optional file output
        if args.output:
            try:
                with open(args.output, 'a', encoding='utf-8') as f:
                    f.write(f"\n[{timestamp}] Results for {len(urls)} URL(s)\n")
                    for _, data in sorted(results.items()):
                        url = data.get("input_url") or data.get("checked_url")
                        status = data.get("status_code") or "Invalid"
                        ip = data.get("original_ip_port") or "IP:Port Not Found"
                        redirect = data.get("final_url")
                        redirect_ip = data.get("redirect_ip_port")
                        redirect_str = f"Redirect: {redirect} ({redirect_ip})" if redirect else "Redirect: None"
                        line = f"[Status: {status}] [IP: {ip}] [Time: {data.get('elapsed_ms') or '?'}ms] {url} [{redirect_str}]\n"
                        f.write(line)
            except Exception:
                pass
        # Notifications on transitions
        if settings["notify"] != "none" and recipients:
            for _, data in results.items():
                url = data.get("input_url") or data.get("checked_url")
                status = data.get("status_code")
                is_up_now = isinstance(status, int) and 200 <= status < 400
                was_up = last_status_up.get(url)
                last_status_up[url] = is_up_now
                # Notify on first observation if down, and on transitions from up -> down
                if was_up is None:
                    if not is_up_now:
                        subject = f"ALERT: {url} is DOWN (status: {status})"
                        body = build_down_message(url, data)
                        ok = send_email_via_smtp(
                            settings["smtp_server"],
                            settings["smtp_port"],
                            settings["smtp_username"],
                            smtp_pw,
                            subject,
                            body,
                            settings.get("email") or settings.get("smtp_username") or "",
                            recipients,
                        )
                        if ok:
                            print(f"Alert sent for {url} to:", ", ".join(recipients))
                        else:
                            if DEBUG:
                                print(f"Warning: Failed to send alert for {url}. Check email/app password and provider settings.")
                else:
                    if was_up and not is_up_now:
                        subject = f"ALERT: {url} is DOWN (status: {status})"
                        body = build_down_message(url, data)
                        ok = send_email_via_smtp(
                            settings["smtp_server"],
                            settings["smtp_port"],
                            settings["smtp_username"],
                            smtp_pw,
                            subject,
                            body,
                            settings.get("email") or settings.get("smtp_username") or "",
                            recipients,
                        )
                        if ok:
                            print(f"Alert sent for {url} to:", ", ".join(recipients))
                        else:
                            if DEBUG:
                                print(f"Warning: Failed to send alert for {url}. Check email/app password and provider settings.")
                    elif (not was_up) and is_up_now:
                        # Optional: notify recovery? Keep silent to avoid noise.
                        pass
        return results

    if settings["monitor"]:
        print(f"Monitoring every {settings['interval']}s. Press Ctrl+C to stop.")
        try:
            first = True
            while True:
                await do_one_cycle(first_cycle=first)
                first = False
                # Add visible vertical spacing before the next loading bar
                try:
                    print("\n" * 5, end="")
                except Exception:
                    pass
                # Show a progress bar for the waiting period until next check
                try:
                    total_wait = max(1, int(settings["interval"]))
                except Exception:
                    total_wait = 60
                # Longer, full-width wait bar
                try:
                    term_cols = shutil.get_terminal_size((100, 40)).columns
                except Exception:
                    term_cols = 100
                bar_cols = max(60, term_cols - 34)  # leave room for label/stats
                try:
                    if tqdm is not None:
                        with tqdm(total=total_wait, desc="Next check", ncols=bar_cols + 24, ascii=True) as pbar:
                            for _ in range(total_wait):
                                await asyncio.sleep(1)
                                pbar.update(1)
                    else:
                        for _ in range(total_wait):
                            print("█", end="", flush=True)
                            await asyncio.sleep(1)
                        print()
                except Exception:
                    await asyncio.sleep(total_wait)
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user.")
    else:
        # Single run
        await do_one_cycle(first_cycle=True)

if __name__ == "__main__":
    asyncio.run(main())
