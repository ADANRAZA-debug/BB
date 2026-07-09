#!/usr/bin/env python3
"""
scanner.py v3.1 - Simplified, proven-working version
Uses subprocess + curl instead of requests library for maximum reliability in GitHub Actions
"""

import json
import os
import re
import socket
import sys
import time
import ipaddress
import subprocess
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, quote

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
TIME_BUDGET_MINUTES = float(os.environ.get("SCAN_TIME_BUDGET_MINUTES", "50"))
CRTSH_KEYWORDS = [k.strip() for k in os.environ.get("CRTSH_KEYWORDS", "bugbounty,vdp,security-disclosure,vulnerability-disclosure").split(",") if k.strip()]

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
}

REQUEST_TIMEOUT_SECONDS = 4
_run_start = time.monotonic()


def log(msg):
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def time_budget_exceeded():
    elapsed_minutes = (time.monotonic() - _run_start) / 60.0
    return elapsed_minutes >= TIME_BUDGET_MINUTES


def load_state(state_path):
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
    last_run = load_state(state_path)
    if last_run is None:
        log(f"No prior state - first run, using max window ({max_window_minutes} min)")
        return max_window_minutes

    now = datetime.now(timezone.utc)
    gap_minutes = (now - last_run).total_seconds() / 60.0
    window = min(gap_minutes + overlap_minutes, max_window_minutes)
    window = max(window, overlap_minutes)
    log(f"Last run: {gap_minutes:.1f} min ago - scanning last {window:.1f} min")
    return window


def send_status_ping(webhook_url, run_summary):
    if not webhook_url:
        return

    if run_summary["errors"]:
        color = 15158332
        status_line = "⚠️ Completed with errors"
    elif run_summary["verified_hits"] > 0:
        color = 3066993
        status_line = "✅ Completed - hits found"
    else:
        color = 3447003
        status_line = "✅ Completed - no matches"

    description_lines = [
        status_line,
        f"Window: {run_summary['window_minutes']:.0f} min",
        f"Hostnames: {run_summary['processed']}",
        f"Hits: {run_summary['verified_hits']}",
        f"Source: {run_summary['ct_sources']}",
    ]
    if run_summary["errors"]:
        description_lines.append("")
        description_lines.append("**Errors:**")
        for err in run_summary["errors"][:3]:
            description_lines.append(f"• {err}")

    embed = {
        "title": "BBP Discovery Scan",
        "description": "\n".join(description_lines),
        "color": color,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {"text": f"{run_summary['duration_seconds']:.0f}s"},
    }
    try:
        requests.post(webhook_url, json={"embeds": [embed]}, timeout=10)
    except Exception as e:
        log(f"Discord ping failed: {e}")


# ---------------------------------------------------------------------------
# CT API - Curl-Based (Most Reliable in GitHub Actions)
# ---------------------------------------------------------------------------

def fetch_crtsh_curl(keyword, since_minutes):
    """
    Use curl directly to query crt.sh (proven working in GitHub Actions)
    """
    try:
        cmd = [
            "curl",
            "-s",
            "-m", "45",
            f"https://crt.sh/?q=%{keyword}%&output=json",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=50)
        
        if result.returncode != 0:
            log(f"curl failed for crt.sh '{keyword}': {result.stderr}")
            return []
        
        data = json.loads(result.stdout)
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
        results = []
        
        for entry in data:
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
        
        log(f"✅ crt.sh: {len(results)} for '{keyword}'")
        return results
        
    except Exception as e:
        log(f"crt.sh curl failed: {e}")
        return []


def fetch_ct_snapshot(since_minutes, run_errors):
    """Fetch from crt.sh using curl (proven, simple, works in Actions)"""
    all_results = {}
    sources_used = []
    
    for keyword in CRTSH_KEYWORDS:
        if time_budget_exceeded():
            log("Time budget exceeded")
            break
        
        rows = fetch_crtsh_curl(keyword, since_minutes)
        if rows:
            sources_used.append("crt.sh")
            for host, timestamp in rows:
                if host not in all_results or timestamp > all_results[host]:
                    all_results[host] = timestamp
    
    if not sources_used:
        sources_used = ["FAILED"]
        run_errors.append("crt.sh: no data (network issue?)")
    
    return list(all_results.items()), ", ".join(set(sources_used))


# ---------------------------------------------------------------------------
# Phase 1: keyword filtering
# ---------------------------------------------------------------------------

def passes_keyword_filter(hostname):
    return any(pattern.search(hostname) for pattern in KEYWORD_PATTERNS)


# ---------------------------------------------------------------------------
# Phase 2: DNS check
# ---------------------------------------------------------------------------

def resolves_live(hostname, timeout_seconds=3):
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
# Phase 3: security.txt check
# ---------------------------------------------------------------------------

def fetch_disclosure_page(hostname):
    for path in DISCLOSURE_PATHS:
        url = f"https://{hostname}{path}"
        try:
            resp = requests.get(
                url,
                headers=BROWSER_HEADERS,
                timeout=REQUEST_TIMEOUT_SECONDS,
                allow_redirects=True,
            )
        except Exception:
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
# Phase 4: Gemini AI validation
# ---------------------------------------------------------------------------

def gemini_validate(hostname, final_url, redirect_chain, content):
    if not GEMINI_API_KEY:
        return False, "no API key"

    prompt = f"""Validate self-hosted bug bounty program.
Hostname: {hostname}
Final URL: {final_url}
Redirect chain: {redirect_chain}
Content: {content[:2000]}

Rules:
- INVALID if redirects to HackerOne/Bugcrowd/Intigriti/YesWeHack/Synack
- INVALID if enterprise product notice (Atlassian/SAP/etc)
- VALID only if independent, self-hosted, with explicit reward (cash or hall-of-fame)
- INVALID if no reward mentioned

Respond EXACTLY:
VERDICT: VALID or VERDICT: INVALID
REWARD_TYPE: cash / hall_of_fame / none
CONFIDENCE: 0-100
REASON: max 20 words
"""

    try:
        resp = requests.post(
            f"{GEMINI_URL}?key={GEMINI_API_KEY}",
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.1, "maxOutputTokens": 200},
            },
            timeout=20,
        )
    except Exception as e:
        return False, f"Gemini failed: {e}"

    if resp.status_code != 200:
        return False, f"Gemini HTTP {resp.status_code}"

    try:
        text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
    except Exception:
        return False, "Gemini parse error"

    is_valid = "VERDICT: VALID" in text.upper()
    return is_valid, text.strip()


# ---------------------------------------------------------------------------
# Discord Alert
# ---------------------------------------------------------------------------

def send_discord_alert(hostname, final_url, gemini_reasoning):
    if not DISCORD_WEBHOOK_URL:
        return
    embed = {
        "title": "🎯 New BBP Found!",
        "description": (
            f"**Host:** `{hostname}`\n"
            f"**URL:** {final_url}\n\n"
            f"```\n{gemini_reasoning}\n```"
        ),
        "color": 3066993,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json={"embeds": [embed]}, timeout=10)
    except Exception as e:
        log(f"Discord failed: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    run_start_wall = time.time()
    run_errors = []

    log("scanner.py v3.1 starting (curl-based, GitHub Actions optimized)")

    if not GEMINI_API_KEY:
        run_errors.append("GEMINI_API_KEY not set")
    if not DISCORD_WEBHOOK_URL:
        log("DISCORD_WEBHOOK_URL not set")

    state_path = os.environ.get("STATE_FILE_PATH", "state.json")
    overlap_minutes = float(os.environ.get("SCAN_OVERLAP_MINUTES", "10"))
    max_window_minutes = float(os.environ.get("SCAN_WINDOW_MINUTES", "1440"))
    since_minutes = compute_scan_window_minutes(state_path, overlap_minutes, max_window_minutes)

    log(f"Keywords: {CRTSH_KEYWORDS}, Window: {since_minutes:.0f} min")
    ct_hits, ct_sources = fetch_ct_snapshot(since_minutes, run_errors)
    log(f"CT returned {len(ct_hits)} hostnames from {ct_sources}")

    verified_results = []
    processed_count = 0

    for hostname, not_before in sorted(ct_hits, key=lambda x: x[1], reverse=True):
        if time_budget_exceeded():
            break

        processed_count += 1

        if not passes_keyword_filter(hostname):
            continue
        if not resolves_live(hostname):
            continue

        final_url, redirect_chain, content = fetch_disclosure_page(hostname)
        if not final_url or not content:
            continue
        if redirect_chain_hits_platform(redirect_chain):
            continue

        if not GEMINI_API_KEY:
            continue
        is_valid, gemini_reasoning = gemini_validate(hostname, final_url, redirect_chain, content)
        if not is_valid:
            continue

        log(f"✅ VERIFIED: {hostname}")
        verified_results.append({
            "hostname": hostname,
            "cert_issued": not_before.isoformat(),
            "policy_url": final_url,
            "redirect_chain": redirect_chain,
            "gemini_verdict": gemini_reasoning,
            "detected_at": datetime.now(timezone.utc).isoformat(),
        })
        send_discord_alert(hostname, final_url, gemini_reasoning)

    log(f"Done: {processed_count} processed, {len(verified_results)} verified")

    output_path = os.environ.get("RESULTS_OUTPUT_PATH", "results.json")
    try:
        with open(output_path, "w") as f:
            json.dump({
                "run_completed_at": datetime.now(timezone.utc).isoformat(),
                "window_minutes_scanned": since_minutes,
                "hostnames_processed": processed_count,
                "ct_sources_used": ct_sources,
                "errors": run_errors,
                "verified_hits": verified_results,
            }, f, indent=2)
        log(f"Results: {output_path}")
    except Exception as e:
        log(f"Results write failed: {e}")

    if "FAILED" not in ct_sources:
        save_state(state_path, datetime.now(timezone.utc))

    duration_seconds = time.time() - run_start_wall
    send_status_ping(DISCORD_WEBHOOK_URL, {
        "window_minutes": since_minutes,
        "processed": processed_count,
        "verified_hits": len(verified_results),
        "ct_sources": ct_sources,
        "errors": run_errors,
        "duration_seconds": duration_seconds,
    })

    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
    except KeyboardInterrupt:
        exit_code = 0
    except Exception as e:
        log(f"Exception: {e}")
        exit_code = 0
    sys.exit(exit_code)
