"""
PAN-OS Live Documentation Research Module
Extracted from pan_tools.py — separate concern from PAN-OS API operations.

Contains: search_live_docs
"""

import os
import logging
import requests

logger = logging.getLogger(__name__)


def search_live_docs(query: str) -> str:
    """
    Searches official Palo Alto Networks documentation via Google Custom Search.
    Use ONLY for PAN-OS documentation lookups, CVE research, or KB article searches.

    Use this when asked: "Search the docs for CVE-2024-3400",
    "What does the PAN-OS admin guide say about App-ID?",
    "Find the KB article for GlobalProtect timeout".

    Do NOT use this for firewall behavior questions — use operational tools
    (test_security_policy, get_live_config) instead.

    Args:
        query (str): The search term (e.g., 'CVE-2024-3400', 'App-ID decoder').
    """
    api_key = os.getenv("GOOGLE_SEARCH_API_KEY")
    cse_id = os.getenv("GOOGLE_CSE_ID")

    if not api_key or not cse_id:
        return "Error: Live Research API not configured (Missing GOOGLE_SEARCH_API_KEY or GOOGLE_CSE_ID)."

    url = "https://www.googleapis.com/customsearch/v1"
    refined_query = f"{query} site:docs.paloaltonetworks.com/"

    params = {
        'q': refined_query,
        'key': api_key,
        'cx': cse_id,
        'num': 5
    }

    try:
        r = requests.get(url, params=params, timeout=10)
        if r.status_code != 200:
            logger.error(f"Live Research Failed: HTTP {r.status_code} - {r.text}")
            return f"Live Research Failed: HTTP {r.status_code} (Details in server logs)"

        data = r.json()
        items = data.get('items', [])

        if not items:
            return f"No live documentation found for: '{query}' on official Palo Alto domains."

        results = [f"--- LIVE RESEARCH RESULTS FOR '{query}' ---"]
        for item in items:
            results.append(f"TITLE: {item.get('title')}\nURL: {item.get('link')}\nSNIPPET: {item.get('snippet')}\n")

        return "\n".join(results)

    except Exception as e:
        logger.error(f"Live Research Execution Failed: {e}")
        return "Live Research Execution Failed. Check server logs for details."
