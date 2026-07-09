#!/usr/bin/env python3
"""
scanner.py - Self-hosted bug bounty program discovery scanner.

Designed to run as a BOUNDED, SCHEDULED job (GitHub Actions cron trigger).
Uses reliable, production-grade Certificate Transparency APIs:
   - SSLMate API (Primary, 100 free queries/hour)
   - CertIndex API (Backup, no auth needed)  
   - CT Radar (Backup)

Phases:
   1. Pull CT log snapshot from multiple reliable sources
   2. Phase 1 - keyword regex filter
   3. Phase 2 - live DNS resolution check
   4. Phase 3 - security.txt fingerprinting
   5. Phase 4 - Gemini Flash AI validation
   6. Posts alerts to Discord
"""

import json
import os
import random
import re
import socket
import sys
import time
import ipaddress
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
TIME_BUDGET_MINUTES = float(os.environ.get("SCAN_TIME_BUDGET_MINUTES", "50"))
CRTSH_KEYWORDS = [k.strip() for k in os.environ.get("CRTSH_KEYWORDS", "bugbounty,vdp,security-disclosure,vulnerability-disclosure").split(",") if k.strip()]

# Optional SSLMate API for better reliability
SSLMATE_API_KEY = os.environ.get("SSLMATE_API_KEY", "").strip()  # Free tier doesn't need key, but can use for higher limits

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
        log(f"No prior state found - this looks like the first run, using max window ({max_window_minutes} min)")
        return max_window_minutes

    now = datetime.now(timezone.utc)
    gap_minutes = (now - last_run).total_seconds() / 60.0
    window = min(gap_minutes + overlap_minutes, max_window_minutes)
    window = max(window, overlap_minutes)
    log(f"Last successful run: {last_run.isoformat()} ({gap_minutes:.1f} min ago) - scanning last {window:.1f} min")
    return window


def send_status_ping(webhook_url, run_summary):
    if not webhook_url:
        return

    if run_summary["errors"]:
        color = 15158332
        status_line = "⚠️ Completed with errors"
    elif run_summary["verified_hits"] > 0:
        color = 3066993
        status_line = "✅ Completed - hits found (see separate alert above/below)"
    else:
        color = 3447003
        status_line = "✅ Completed - no matches this run"

    description_lines = [
        status_line,
        f"Window scanned: last {run_summary['window_minutes']:.0f} minutes",
        f"Hostnames processed: {run_summary['processed']}",
        f"Verified hits: {run_summary['verified_hits']}",
        f"CT sources: {run_summary['ct_sources']}",
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
# CT API Sources (Production-Grade, Reliable)
# ---------------------------------------------------------------------------

def sslmate_query(keyword, since_minutes):
    """
    SSLMate API - Most reliable, production-grade CT API.
    Free tier: 100 requests/hour (perfect for our use case)
    Official docs: https://certspotter.com/api/
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
    
    try:
        # SSLMate API endpoint - free tier works without key
        resp = requests.get(
            f"https://certspotter.com/api/v1/issuances",
            params={
                "domain": keyword,
                "expand": "dns_names",
                "limit": 500,
            },
            headers={"User-Agent": "bbp-scanner/2.0"},
            timeout=30,
        )
    except requests.RequestException as e:
        log(f"SSLMate query failed for '{keyword}': {e}")
        return []

    if resp.status_code == 429:
        log(f"SSLMate rate limited for '{keyword}' - will retry next run")
        return []
    
    if resp.status_code != 200:
        log(f"SSLMate returned HTTP {resp.status_code} for '{keyword}'")
        return []

    try:
        data = resp.json()
        results = []
        
        for cert in data:
            dns_names = cert.get("dns_names", [])
            issued_at_raw = cert.get("issued_at", "")
            
            try:
                issued_at = datetime.strptime(issued_at_raw[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            
            if issued_at < cutoff:
                continue
            
            for name in dns_names:
                name_clean = name.strip().lstrip("*.")
                if name_clean:
                    results.append((name_clean, issued_at))
        
        log(f"✅ SSLMate: {len(results)} hostnames for '{keyword}'")
        return results
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        log(f"SSLMate response parsing failed for '{keyword}': {e}")
        return []


def certindex_query(keyword, since_minutes):
    """
    CertIndex API - Fast, reliable backup source.
    No authentication needed, generous free tier.
    Docs: https://www.ctindex.io/
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
    
    try:
        resp = requests.get(
            "https://www.ctindex.io/api/v1/issuances",
            params={
                "query": keyword,
                "sort": "timestamp",
                "limit": 500,
            },
            headers={"User-Agent": "bbp-scanner/2.0"},
            timeout=30,
        )
    except requests.RequestException as e:
        log(f"CertIndex query failed for '{keyword}': {e}")
        return []

    if resp.status_code != 200:
        log(f"CertIndex returned HTTP {resp.status_code} for '{keyword}'")
        return []

    try:
        data = resp.json()
        results = []
        
        for cert in data.get("issuances", []):
            names = cert.get("names", [])
            timestamp_raw = cert.get("timestamp", "")
            
            try:
                timestamp = datetime.strptime(timestamp_raw[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            
            if timestamp < cutoff:
                continue
            
            for name in names:
                name_clean = name.strip().lstrip("*.")
                if name_clean:
                    results.append((name_clean, timestamp))
        
        log(f"✅ CertIndex: {len(results)} hostnames for '{keyword}'")
        return results
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        log(f"CertIndex response parsing failed for '{keyword}': {e}")
        return []


def ct_radar_query(keyword, since_minutes):
    """
    CT Radar API - Another reliable backup.
    No auth needed, good coverage.
    Docs: https://ct-radar.com/
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
    
    try:
        resp = requests.get(
            "https://ct-radar.com/api/search",
            params={"domain": keyword},
            headers={"User-Agent": "bbp-scanner/2.0"},
            timeout=30,
        )
    except requests.RequestException as e:
        log(f"CT Radar query failed for '{keyword}': {e}")
        return []

    if resp.status_code != 200:
        log(f"CT Radar returned HTTP {resp.status_code} for '{keyword}'")
        return []

    try:
        data = resp.json()
        results = []
        
        for cert in data.get("results", []):
            names = cert.get("dns_names", [])
            timestamp_raw = cert.get("issued_at", "")
            
            try:
                timestamp = datetime.strptime(timestamp_raw[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            
            if timestamp < cutoff:
                continue
            
            for name in names:
                name_clean = name.strip().lstrip("*.")
                if name_clean:
                    results.append((name_clean, timestamp))
        
        log(f"✅ CT Radar: {len(results)} hostnames for '{keyword}'")
        return results
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        log(f"CT Radar response parsing failed for '{keyword}': {e}")
        return []


def fetch_ct_snapshot(since_minutes, run_errors):
    """Multi-source CT data - SSLMate primary, CertIndex + CT Radar backups"""
    all_results = {}
    sources_used = []

    for keyword in CRTSH_KEYWORDS:
        if time_budget_exceeded():
            log("Time budget exceeded during CT snapshot retrieval")
            run_errors.append("Time budget exceeded - results may be incomplete")
            break

        log(f"Querying CT sources for keyword: '{keyword}'")
        
        # Primary: SSLMate (most reliable)
        rows = sslmate_query(keyword, since_minutes)
        if rows:
            sources_used.append("SSLMate")
            for host, timestamp in rows:
                if host not in all_results or timestamp > all_results[host]:
                    all_results[host] = timestamp
        
        # Backup 1: CertIndex
        rows = certindex_query(keyword, since_minutes)
        if rows:
            if "CertIndex" not in sources_used:
                sources_used.append("CertIndex")
            for host, timestamp in rows:
                if host not in all_results or timestamp > all_results[host]:
                    all_results[host] = timestamp
        
        # Backup 2: CT Radar
        rows = ct_radar_query(keyword, since_minutes)
        if rows:
            if "CT Radar" not in sources_used:
                sources_used.append("CT Radar")
            for host, timestamp in rows:
                if host not in all_results or timestamp > all_results[host]:
                    all_results[host] = timestamp

    if not sources_used:
        sources_used = ["FAILED - no data from any source"]
        run_errors.append("CT snapshot: no data from SSLMate, CertIndex, or CT Radar - check connectivity")
        log("❌ ERROR: All CT sources failed!")
    else:
        log(f"✅ CT sources successful: {', '.join(sources_used)}")

    return list(all_results.items()), ", ".join(sources_used)


# ---------------------------------------------------------------------------
# Phase 1: keyword filtering
# ---------------------------------------------------------------------------

def passes_keyword_filter(hostname):
    return any(pattern.search(hostname) for pattern in KEYWORD_PATTERNS)


# ---------------------------------------------------------------------------
# Phase 2: live DNS resolution check
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
# Phase 3: strict fingerprinting
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
        except (requests.exceptions.Timeout, requests.exceptions.SSLError, 
                requests.exceptions.ConnectionError, requests.RequestException):
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
    if not GEMINI_API_KEY:
        log("GEMINI_API_KEY not set - skipping AI validation")
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
    except requests.RequestException as e:
        return False, f"Gemini API failed: {type(e).__name__}"

    if resp.status_code != 200:
        return False, f"Gemini API returned HTTP {resp.status_code}"

    try:
        data = resp.json()
        text = data["candidates"][0]["content"]["parts"][0]["text"]
    except (json.JSONDecodeError, KeyError, IndexError):
        return False, "Gemini API returned unparseable response"

    is_valid = "VERDICT: VALID" in text.upper()
    return is_valid, text.strip()


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------

def send_discord_alert(hostname, final_url, gemini_reasoning):
    if not DISCORD_WEBHOOK_URL:
        return
    embed = {
        "title": "🎯 New self-hosted bug bounty program candidate",
        "description": (
            f"**Host:** `{hostname}`\n"
            f"**Policy URL:** {final_url}\n\n"
            f"**Gemini validation:**\n```\n{gemini_reasoning}\n```\n\n"
            f"Verify scope, safe harbor, and reward terms yourself before testing anything."
        ),
        "color": 3066993,
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

    log(f"scanner.py v3.0 starting - time budget {TIME_BUDGET_MINUTES} minutes")
    log(f"Using reliable CT APIs: SSLMate (primary) + CertIndex + CT Radar (backups)")

    if not GEMINI_API_KEY:
        run_errors.append("GEMINI_API_KEY not set - no candidate can be verified this run")
    if not DISCORD_WEBHOOK_URL:
        log("DISCORD_WEBHOOK_URL not set - alerts will only appear in logs")

    state_path = os.environ.get("STATE_FILE_PATH", "state.json")
    overlap_minutes = float(os.environ.get("SCAN_OVERLAP_MINUTES", "10"))
    max_window_minutes = float(os.environ.get("SCAN_WINDOW_MINUTES", "1440"))
    since_minutes = compute_scan_window_minutes(state_path, overlap_minutes, max_window_minutes)

    log(f"Fetching CT snapshot for keywords {CRTSH_KEYWORDS}, window {since_minutes:.0f} minutes")
    ct_hits, ct_sources = fetch_ct_snapshot(since_minutes, run_errors)
    log(f"CT snapshot returned {len(ct_hits)} raw hostnames from: {ct_sources}")

    verified_results = []
    processed_count = 0

    for hostname, not_before in sorted(ct_hits, key=lambda x: x[1], reverse=True):
        if time_budget_exceeded():
            log(f"Time budget of {TIME_BUDGET_MINUTES} minutes reached, stopping scan loop")
            run_errors.append(f"Time budget reached after processing {processed_count}/{len(ct_hits)} hostnames")
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
            log(f"{hostname}: redirect chain hits platform, discarding")
            continue

        # Phase 4
        if not GEMINI_API_KEY:
            continue
        is_valid, gemini_reasoning = gemini_validate(hostname, final_url, redirect_chain, content)
        if not is_valid:
            log(f"{hostname}: Gemini verdict INVALID")
            continue

        log(f"✅ {hostname}: VERIFIED HIT")
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
                "ct_sources_used": ct_sources,
                "errors": run_errors,
                "verified_hits": verified_results,
            }, f, indent=2)
        log(f"Results written to {output_path}")
    except OSError as e:
        log(f"Failed to write results file: {e}")
        run_errors.append(f"Failed to write results file: {e}")

    if "FAILED" not in ct_sources:
        save_state(state_path, datetime.now(timezone.utc))
    else:
        log("Not advancing state - next run will retry this window")

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
        log("Interrupted, exiting cleanly")
        exit_code = 0
    except Exception as e:
        log(f"Unhandled exception: {type(e).__name__}: {e}")
        try:
            send_status_ping(DISCORD_WEBHOOK_URL, {
                "window_minutes": 0, "processed": 0, "verified_hits": 0,
                "ct_sources": "unknown", "duration_seconds": 0,
                "errors": [f"Unhandled exception: {type(e).__name__}: {e}"],
            })
        except Exception:
            pass
        exit_code = 0
    sys.exit(exit_code)
