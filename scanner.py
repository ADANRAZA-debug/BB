#!/usr/bin/env python3
"""
scanner.py - Self-hosted bug bounty program discovery scanner.

Designed to run as a BOUNDED, SCHEDULED job (GitHub Actions cron trigger),
not a persistent process. If you want a true always-on certstream websocket
listener, run it on a real host you control (a VPS/VM) - GitHub Actions
does not support and does not permit long-running/persistent workloads,
so this script deliberately does one bounded pass per invocation:

  1. Pull a snapshot of recent CT log activity (crt.sh direct Postgres
     connection if available, else its HTTPS JSON API) for a short list
     of security-related keywords.
  2. Phase 1 - keyword regex filter on the resulting hostnames.
  3. Phase 2 - live DNS resolution check (socket) before any HTTP request.
  4. Phase 3 - strict fingerprinting: fetch security.txt / common
     disclosure paths with browser-like headers, 4s timeout, full
     redirect-chain tracking.
  5. Phase 4 - Gemini Flash validation: confirms independent, self-hosted,
     rewarded (cash or hall-of-fame) Web2 program; explicitly rejects
     platform-mediated pages and enterprise/on-prem product security
     notices (e.g. Atlassian, SAP).
  6. Writes verified hits to results.json, posts a rich alert to Discord
     for each one, and posts a brief STATUS PING every run regardless of
     outcome (so you can confirm the schedule is actually firing without
     checking the Actions tab) - includes any errors encountered.

Exits gracefully (code 0) after a configurable time budget so it fits
cleanly inside a scheduled Actions run.

State/continuity across runs:
    GitHub-hosted runners are stateless. state.json (committed back to
    the repo by the workflow after each run) records the last successful
    scan time, so each run only needs to cover the gap since then (plus
    a small safety overlap) instead of re-scanning a fixed window every
    time. First run ever (no state.json) uses SCAN_WINDOW_MINUTES as a
    one-time fallback.

Environment variables required:
    GEMINI_API_KEY       - https://aistudio.google.com/apikey (free tier)

Environment variables optional:
    DISCORD_WEBHOOK_URL       - alerts + status pings posted here if set
    SCAN_TIME_BUDGET_MINUTES  - default 50
    SCAN_WINDOW_MINUTES       - max/fallback window in minutes, default 1440
    SCAN_OVERLAP_MINUTES      - safety overlap added to the gap since last run, default 10
    CRTSH_KEYWORDS            - comma-separated, default "bugbounty,vdp"
    STATE_FILE_PATH           - default "state.json"
    RESULTS_OUTPUT_PATH       - default "results.json"
"""

import json
import os
import re
import socket
import sys
import time
import ipaddress
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests

try:
    import psycopg2
    HAVE_PSYCOPG2 = True
except ImportError:
    HAVE_PSYCOPG2 = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
TIME_BUDGET_MINUTES = float(os.environ.get("SCAN_TIME_BUDGET_MINUTES", "50"))
CRTSH_KEYWORDS = [k.strip() for k in os.environ.get("CRTSH_KEYWORDS", "bugbounty,vdp").split(",") if k.strip()]

GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

KEYWORD_PATTERNS = [
    re.compile(r"bounty", re.IGNORECASE),
    re.compile(r"security", re.IGNORECASE),
    re.compile(r"disclosure", re.IGNORECASE),
    re.compile(r"vulnerability", re.IGNORECASE),
    re.compile(r"bugbounty", re.IGNORECASE),
    re.compile(r"security-txt", re.IGNORECASE),
    re.compile(r"vdp", re.IGNORECASE),
]

DISCLOSURE_PATHS = [
    "/.well-known/security.txt",
    "/security.txt",
    "/security",
    "/bug-bounty",
]

PLATFORM_PATTERNS = [
    re.compile(r"hackerone\.com", re.IGNORECASE),
    re.compile(r"bugcrowd\.com", re.IGNORECASE),
    re.compile(r"intigriti\.com", re.IGNORECASE),
    re.compile(r"yeswehack\.com", re.IGNORECASE),
    re.compile(r"synack\.com", re.IGNORECASE),
]

BROWSER_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

REQUEST_TIMEOUT_SECONDS = 4
CRTSH_MIN_INTERVAL_SECONDS = 13.0  # respects crt.sh's real 5 req/min HTTPS limit
_last_crtsh_call = [0.0]
_run_start = time.monotonic()


def log(msg):
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def time_budget_exceeded():
    elapsed_minutes = (time.monotonic() - _run_start) / 60.0
    return elapsed_minutes >= TIME_BUDGET_MINUTES


def load_state(state_path):
    """
    Reads the last successful run's timestamp from a small state file
    committed back into the repo (GitHub-hosted runners are stateless, so
    this file is how continuity survives between separate scheduled runs).
    Returns a datetime, or None if this is the first-ever run / file is
    missing or corrupt.
    """
    if not os.path.exists(state_path):
        return None
    try:
        with open(state_path) as f:
            data = json.load(f)
        return datetime.fromisoformat(data["last_successful_scan"])
    except (json.JSONDecodeError, KeyError, ValueError, OSError):
        return None


def save_state(state_path, timestamp):
    try:
        with open(state_path, "w") as f:
            json.dump({"last_successful_scan": timestamp.isoformat()}, f, indent=2)
    except OSError as e:
        log(f"Failed to write state file: {e}")


def compute_scan_window_minutes(state_path, overlap_minutes, max_window_minutes):
    """
    Scans exactly the gap since the last successful run, plus a small
    safety overlap in case a previous run failed partway through or CT
    log propagation lagged. Falls back to max_window_minutes if there's
    no prior state (first run) or the gap is implausibly large (state
    file stale/corrupted, or the schedule was paused for a long time).
    """
    last_run = load_state(state_path)
    if last_run is None:
        log(f"No prior state found - this looks like the first run, using max window ({max_window_minutes} min)")
        return max_window_minutes

    now = datetime.now(timezone.utc)
    gap_minutes = (now - last_run).total_seconds() / 60.0
    window = min(gap_minutes + overlap_minutes, max_window_minutes)
    window = max(window, overlap_minutes)  # never scan a window smaller than the overlap itself
    log(f"Last successful run: {last_run.isoformat()} ({gap_minutes:.1f} min ago) - scanning last {window:.1f} min")
    return window


def send_status_ping(webhook_url, run_summary):
    """
    Brief 'I'm alive and here's what happened' ping sent on EVERY run,
    separate from the rich per-hit alert. Lets you confirm the schedule
    is actually firing without having to check the Actions tab.
    """
    if not webhook_url:
        return

    if run_summary["errors"]:
        color = 15158332  # red - something needs attention
        status_line = "⚠️ Completed with errors"
    elif run_summary["verified_hits"] > 0:
        color = 3066993  # green - found something
        status_line = "✅ Completed - hits found (see separate alert above/below)"
    else:
        color = 3447003  # blue - normal, nothing found
        status_line = "✅ Completed - no matches this run"

    description_lines = [
        status_line,
        f"Window scanned: last {run_summary['window_minutes']:.0f} minutes",
        f"Hostnames processed: {run_summary['processed']}",
        f"Verified hits: {run_summary['verified_hits']}",
        f"crt.sh path used: {run_summary['crtsh_path']}",
    ]
    if run_summary["errors"]:
        description_lines.append("")
        description_lines.append("**Errors:**")
        for err in run_summary["errors"][:5]:
            description_lines.append(f"- {err}")

    embed = {
        "title": "BBP Discovery Scan - Status",
        "description": "\n".join(description_lines),
        "color": color,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {"text": f"Run duration: {run_summary['duration_seconds']:.0f}s"},
    }
    try:
        requests.post(webhook_url, json={"embeds": [embed]}, timeout=10)
    except requests.RequestException as e:
        log(f"Status ping failed to send: {e}")


# ---------------------------------------------------------------------------
# CT log snapshot retrieval (crt.sh direct DB preferred, HTTPS JSON fallback)
# ---------------------------------------------------------------------------

def crtsh_query_db(keyword, since_minutes):
    """
    Direct connection to crt.sh's public, read-only Postgres database
    (psql -h crt.sh -p 5432 -U guest certwatch - officially documented by
    crt.sh's maintainer). Bypasses the HTTPS proxy's rate limit/timeout.
    Returns a list of (hostname, not_before) tuples, or None on failure.
    """
    if not HAVE_PSYCOPG2:
        return None
    try:
        conn = psycopg2.connect(
            host="crt.sh", port=5432, dbname="certwatch", user="guest",
            connect_timeout=15,
            options="-c statement_timeout=45000",
        )
        conn.autocommit = True
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
        sql = """
            SELECT DISTINCT ci.NAME_VALUE, x509_notBefore(c.CERTIFICATE) AS not_before
            FROM certificate_and_identities ci
            JOIN certificate c ON ci.CERTIFICATE_ID = c.ID
            WHERE ci.NAME_VALUE ILIKE %s
              AND x509_notBefore(c.CERTIFICATE) > %s
            ORDER BY not_before DESC
            LIMIT 500;
        """
        try:
            with conn.cursor() as cur:
                cur.execute(sql, (f"%{keyword}%", cutoff))
                rows = cur.fetchall()
                return [(r[0], r[1]) for r in rows]
        finally:
            conn.close()
    except Exception as e:
        log(f"crt.sh direct DB query failed for '{keyword}': {type(e).__name__}: {e}")
        return None


def crtsh_query_https(keyword, since_minutes):
    """HTTPS JSON API fallback - rate-limited to respect crt.sh's real
    5 requests/minute limit per IP."""
    elapsed = time.time() - _last_crtsh_call[0]
    if elapsed < CRTSH_MIN_INTERVAL_SECONDS:
        time.sleep(CRTSH_MIN_INTERVAL_SECONDS - elapsed)
    _last_crtsh_call[0] = time.time()

    try:
        resp = requests.get(
            "https://crt.sh/",
            params={"q": f"%{keyword}%", "output": "json"},
            timeout=45,
            headers={"User-Agent": "scanner.py/1.0"},
        )
    except requests.exceptions.Timeout:
        log(f"crt.sh HTTPS query timed out for '{keyword}'")
        return []
    except requests.exceptions.ConnectionError as e:
        log(f"crt.sh HTTPS connection failed for '{keyword}': {e}")
        return []
    except requests.RequestException as e:
        log(f"crt.sh HTTPS request failed for '{keyword}': {e}")
        return []

    if resp.status_code != 200:
        log(f"crt.sh HTTPS returned HTTP {resp.status_code} for '{keyword}'")
        return []

    try:
        entries = resp.json()
    except json.JSONDecodeError:
        log(f"crt.sh HTTPS returned non-JSON for '{keyword}' (likely rate-limited/overloaded)")
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
    results = []
    for entry in entries:
        not_before_raw = entry.get("not_before", "")
        try:
            not_before = datetime.strptime(not_before_raw[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if not_before < cutoff:
            continue
        name_value = entry.get("name_value", "")
        for host in set(name_value.split("\n")):
            host = host.strip().lstrip("*.")
            if host:
                results.append((host, not_before))
    return results


def fetch_ct_snapshot(since_minutes, run_errors):
    """Returns (results, path_used) - deduplicated list of (hostname,
    not_before) tuples across all configured keywords, using the direct
    DB path when available, plus a label of which path actually worked."""
    all_results = {}
    used_db = False
    used_https = False
    any_keyword_failed = False

    for keyword in CRTSH_KEYWORDS:
        if time_budget_exceeded():
            log("Time budget exceeded during CT snapshot retrieval, stopping early")
            run_errors.append("Time budget exceeded during CT snapshot retrieval - results may be incomplete")
            break
        rows = crtsh_query_db(keyword, since_minutes)
        if rows is not None:
            used_db = True
        else:
            log(f"Falling back to crt.sh HTTPS JSON API for keyword '{keyword}' (psycopg2 unavailable or DB query failed)")
            rows = crtsh_query_https(keyword, since_minutes)
            if rows:
                used_https = True
            else:
                any_keyword_failed = True
        for host, not_before in rows:
            if host not in all_results or not_before > all_results[host]:
                all_results[host] = not_before

    if used_db and used_https:
        path_used = "direct DB (partial) + HTTPS fallback"
    elif used_db:
        path_used = "direct DB"
    elif used_https:
        path_used = "HTTPS JSON (fallback)"
    else:
        path_used = "FAILED - no data retrieved"
        run_errors.append("crt.sh returned no data on either path (direct DB or HTTPS) - check connectivity")

    if any_keyword_failed and used_db is False and used_https is False:
        pass  # already captured above

    return list(all_results.items()), path_used


# ---------------------------------------------------------------------------
# Phase 1: keyword filtering
# ---------------------------------------------------------------------------

def passes_keyword_filter(hostname):
    return any(pattern.search(hostname) for pattern in KEYWORD_PATTERNS)


# ---------------------------------------------------------------------------
# Phase 2: live DNS resolution check
# ---------------------------------------------------------------------------

def resolves_live(hostname, timeout_seconds=3):
    """Confirms the hostname actually resolves before any HTTP request is
    attempted. Pure DNS lookup - no port scanning, no connection to the
    target's infrastructure beyond standard name resolution."""
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout_seconds)
    try:
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            addr = info[4][0]
            try:
                ip_obj = ipaddress.ip_address(addr)
                if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local:
                    continue
                return True
            except ValueError:
                continue
        return False
    except (socket.gaierror, socket.timeout, OSError):
        return False
    finally:
        socket.setdefaulttimeout(old_timeout)


# ---------------------------------------------------------------------------
# Phase 3: strict fingerprinting
# ---------------------------------------------------------------------------

def fetch_disclosure_page(hostname):
    """
    Fetches known disclosure-policy paths with browser-like headers, a
    strict 4-second timeout, and full redirect-chain tracking. Every
    request here is a single, standard, unauthenticated GET to a page an
    org has published for public/researcher reading - no enumeration, no
    port probing, no authentication bypass attempts.
    Returns (final_url, redirect_chain, content) or (None, [], None).
    """
    for path in DISCLOSURE_PATHS:
        url = f"https://{hostname}{path}"
        try:
            resp = requests.get(
                url,
                headers=BROWSER_HEADERS,
                timeout=REQUEST_TIMEOUT_SECONDS,
                allow_redirects=True,
            )
        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.SSLError:
            continue
        except requests.exceptions.ConnectionError:
            continue
        except requests.RequestException:
            continue

        if resp.status_code != 200:
            continue

        redirect_chain = [r.url for r in resp.history] + [resp.url]
        content_lower = resp.text.lower()
        signal_words = ("responsible disclosure", "bug bounty", "vulnerability disclosure",
                         "security researcher", "report a vulnerability", "safe harbor",
                         "hall of fame", "reward")
        signal_count = sum(1 for w in signal_words if w in content_lower)
        if signal_count >= 1:
            return resp.url, redirect_chain, resp.text

    return None, [], None


def redirect_chain_hits_platform(redirect_chain):
    joined = " ".join(redirect_chain).lower()
    return any(pattern.search(joined) for pattern in PLATFORM_PATTERNS)


# ---------------------------------------------------------------------------
# Phase 4: Gemini Flash AI validation
# ---------------------------------------------------------------------------

def gemini_validate(hostname, final_url, redirect_chain, content):
    """
    Sends the fetched page content to Gemini Flash for context validation.
    The model must explicitly return VERDICT: VALID or VERDICT: INVALID,
    with INVALID required for: platform-mediated redirects (HackerOne,
    Bugcrowd, Intigriti, YesWeHack, Synack) or on-prem enterprise product
    security notices (e.g. Atlassian, SAP) that are not independent
    programs run by the domain owner itself.
    """
    if not GEMINI_API_KEY:
        log("GEMINI_API_KEY not set - skipping AI validation, cannot confirm this hit")
        return False, "no Gemini API key configured"

    prompt = f"""You are validating a candidate self-hosted bug bounty / vulnerability
disclosure program page for a security research tool. Analyze the page content below.

Hostname: {hostname}
Final URL after redirects: {final_url}
Redirect chain: {redirect_chain}

Page content (truncated):
{content[:3000]}

Rules:
- Return VERDICT: INVALID if the redirect chain or content shows this page
  is actually hosted on or redirects to HackerOne, Bugcrowd, Intigriti,
  YesWeHack, or Synack (platform-mediated, not self-hosted).
- Return VERDICT: INVALID if this is an enterprise/on-prem PRODUCT security
  notice page (e.g. a generic Atlassian, SAP, or similar vendor security
  advisory page) rather than an independent program run by the domain
  owner about their own assets.
- Return VERDICT: VALID only if this is an independent, self-hosted Web2
  program, run by the domain owner, that explicitly offers a reward -
  either financial (cash bounty) or non-financial (hall of fame / swag).
- Return VERDICT: INVALID if there is no explicit reward mentioned at all
  (report-only policy with nothing offered in return).

Respond in EXACTLY this format, nothing else:
VERDICT: VALID or VERDICT: INVALID
REWARD_TYPE: cash / hall_of_fame / none
CONFIDENCE: 0-100
REASON: one sentence, max 25 words
"""

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.1, "maxOutputTokens": 200},
    }

    try:
        resp = requests.post(
            f"{GEMINI_URL}?key={GEMINI_API_KEY}",
            json=payload,
            timeout=20,
            headers={"Content-Type": "application/json"},
        )
    except requests.exceptions.Timeout:
        return False, "Gemini API request timed out"
    except requests.RequestException as e:
        return False, f"Gemini API request failed: {type(e).__name__}"

    if resp.status_code != 200:
        return False, f"Gemini API returned HTTP {resp.status_code}"

    try:
        data = resp.json()
        text = data["candidates"][0]["content"]["parts"][0]["text"]
    except (json.JSONDecodeError, KeyError, IndexError):
        return False, "Gemini API returned an unparseable response"

    is_valid = "VERDICT: VALID" in text.upper()
    return is_valid, text.strip()


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------

def send_discord_alert(hostname, final_url, gemini_reasoning):
    if not DISCORD_WEBHOOK_URL:
        return
    embed = {
        "title": "New self-hosted bug bounty program candidate",
        "description": (
            f"**Host:** `{hostname}`\n"
            f"**Policy URL:** {final_url}\n\n"
            f"**Gemini validation:**\n```\n{gemini_reasoning}\n```\n\n"
            f"Verify scope, safe harbor, and reward terms yourself before testing anything."
        ),
        "color": 15158332,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json={"embeds": [embed]}, timeout=10)
    except requests.RequestException as e:
        log(f"Discord webhook post failed: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    run_start_wall = time.time()
    run_errors = []

    log(f"scanner.py starting - time budget {TIME_BUDGET_MINUTES} minutes")
    log(f"Direct crt.sh Postgres access: {'available' if HAVE_PSYCOPG2 else 'not installed, using HTTPS fallback'}")

    if not GEMINI_API_KEY:
        run_errors.append("GEMINI_API_KEY not set - no candidate can be verified this run")
    if not DISCORD_WEBHOOK_URL:
        log("DISCORD_WEBHOOK_URL not set - alerts and status pings will only appear in logs")

    state_path = os.environ.get("STATE_FILE_PATH", "state.json")
    overlap_minutes = float(os.environ.get("SCAN_OVERLAP_MINUTES", "10"))
    max_window_minutes = float(os.environ.get("SCAN_WINDOW_MINUTES", "1440"))
    since_minutes = compute_scan_window_minutes(state_path, overlap_minutes, max_window_minutes)

    log(f"Fetching CT snapshot for keywords {CRTSH_KEYWORDS}, window {since_minutes:.0f} minutes")
    ct_hits, crtsh_path_used = fetch_ct_snapshot(since_minutes, run_errors)
    log(f"CT snapshot returned {len(ct_hits)} raw hostnames via: {crtsh_path_used}")

    verified_results = []
    processed_count = 0

    for hostname, not_before in sorted(ct_hits, key=lambda x: x[1], reverse=True):
        if time_budget_exceeded():
            log(f"Time budget of {TIME_BUDGET_MINUTES} minutes reached, stopping scan loop cleanly")
            run_errors.append(f"Time budget reached after processing {processed_count}/{len(ct_hits)} hostnames - remainder will be caught next run via overlap window")
            break

        processed_count += 1

        # Phase 1
        if not passes_keyword_filter(hostname):
            continue

        # Phase 2
        if not resolves_live(hostname):
            continue

        # Phase 3
        final_url, redirect_chain, content = fetch_disclosure_page(hostname)
        if not final_url or not content:
            continue
        if redirect_chain_hits_platform(redirect_chain):
            log(f"{hostname}: redirect chain hits a known platform, discarding")
            continue

        # Phase 4
        if not GEMINI_API_KEY:
            continue  # already flagged in run_errors above; can't verify without it
        is_valid, gemini_reasoning = gemini_validate(hostname, final_url, redirect_chain, content)
        if not is_valid:
            log(f"{hostname}: Gemini verdict INVALID - {gemini_reasoning[:100]}")
            continue

        log(f"{hostname}: VERIFIED HIT")
        verified_results.append({
            "hostname": hostname,
            "cert_issued": not_before.isoformat(),
            "policy_url": final_url,
            "redirect_chain": redirect_chain,
            "gemini_verdict": gemini_reasoning,
            "detected_at": datetime.now(timezone.utc).isoformat(),
        })
        send_discord_alert(hostname, final_url, gemini_reasoning)

    log(f"Scan complete: {processed_count} hostnames processed, {len(verified_results)} verified hits")

    output_path = os.environ.get("RESULTS_OUTPUT_PATH", "results.json")
    try:
        with open(output_path, "w") as f:
            json.dump({
                "run_completed_at": datetime.now(timezone.utc).isoformat(),
                "window_minutes_scanned": since_minutes,
                "hostnames_processed": processed_count,
                "crtsh_path_used": crtsh_path_used,
                "errors": run_errors,
                "verified_hits": verified_results,
            }, f, indent=2)
        log(f"Results written to {output_path}")
    except OSError as e:
        log(f"Failed to write results file: {e}")
        run_errors.append(f"Failed to write results file: {e}")

    # Only advance the state timestamp if the run actually got through the
    # CT fetch stage - if crt.sh totally failed, keep the old timestamp so
    # the next run's overlap window still covers this gap instead of
    # silently skipping it.
    if crtsh_path_used != "FAILED - no data retrieved":
        save_state(state_path, datetime.now(timezone.utc))
    else:
        log("Not advancing state timestamp since this run got no CT data - next run will retry this window")

    duration_seconds = time.time() - run_start_wall
    send_status_ping(DISCORD_WEBHOOK_URL, {
        "window_minutes": since_minutes,
        "processed": processed_count,
        "verified_hits": len(verified_results),
        "crtsh_path": crtsh_path_used,
        "errors": run_errors,
        "duration_seconds": duration_seconds,
    })

    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
    except KeyboardInterrupt:
        log("Interrupted, exiting cleanly")
        exit_code = 0
    except Exception as e:
        # Catch-all so a single unhandled exception never fails the whole
        # scheduled Actions run with a red X - log it, try to ping Discord
        # about it too, and exit 0 since this is a best-effort discovery
        # scan, not a required build step.
        log(f"Unhandled exception, exiting cleanly anyway: {type(e).__name__}: {e}")
        try:
            send_status_ping(DISCORD_WEBHOOK_URL, {
                "window_minutes": 0, "processed": 0, "verified_hits": 0,
                "crtsh_path": "unknown", "duration_seconds": 0,
                "errors": [f"Unhandled exception: {type(e).__name__}: {e}"],
            })
        except Exception:
            pass
        exit_code = 0
    sys.exit(exit_code)
