import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

from config import XSS_PAYLOADS, HEADERS, REQUEST_TIMEOUT



def check_xss(url: str, logger: logging.Logger) -> dict:
    logger.info(f"[XSS] Starting XSS test on: {url}")

    result = {
        "vulnerable":    False,
        "findings":      [],
        "tested_params": [],
        "error":         None,
    }

    #  Parse URL 
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        logger.info("[XSS] No query parameters found — testing search-like endpoints")
        test_param_names = ["q", "search", "query", "s", "input", "term", "keyword"]
        for param_name in test_param_names:
            for payload in XSS_PAYLOADS[:3]:
                test_params = {param_name: payload}
                new_query   = urlencode(test_params)
                test_url    = urlunparse(parsed._replace(query=new_query))
                _try_xss_request(test_url, param_name, payload, result, logger)
                if result["vulnerable"]:
                    return result
        return result

    result["tested_params"] = list(params.keys())
    logger.info(f"[XSS] Testing parameters: {result['tested_params']}")

    # Test each parameter 
    for param_name in params:
        for payload in XSS_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload
            new_query = urlencode(test_params, quote_via=lambda s, safe, enc, err: s)
            test_url = urlunparse(parsed._replace(query=new_query))
            _try_xss_request(test_url, param_name, payload, result, logger)

    if not result["vulnerable"]:
        logger.info("[XSS] ✓ No reflected XSS vulnerabilities detected")
    else:
        logger.warning(f"[XSS] {len(result['findings'])} XSS finding(s) confirmed!")

    return result


def _try_xss_request(url: str, param: str, payload: str,
                     result: dict, logger: logging.Logger):
    try:
        resp = requests.get(
            url,
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
        response_text = resp.text

        # Core XSS detection
        if _is_payload_reflected(payload, response_text):
            result["vulnerable"] = True
            finding = {
                "url":       url,
                "parameter": param,
                "payload":   payload,
                "evidence":  _extract_reflected_context(payload, response_text),
                "status_code": resp.status_code,
            }
            result["findings"].append(finding)
            logger.warning(f"[XSS] ⚠ REFLECTED XSS! param='{param}', payload='{payload[:40]}...'")

    except requests.exceptions.Timeout:
        logger.debug(f"[XSS] Timeout for param='{param}'")
    except Exception as e:
        logger.debug(f"[XSS] Error: {e}")


def _is_payload_reflected(payload: str, response: str) -> bool:
    # Direct reflection check
    if payload in response:
        return True

    # Partial check: script tag ya onerror reflect hua?
    key_parts = ["<script>", "<img ", "onerror=", "onload=", "javascript:"]
    return any(part in response.lower() for part in key_parts if part in payload.lower())


def _extract_reflected_context(payload: str, response: str, window: int = 150) -> str:
    """Response mein se reflected payload ka surrounding context extract karta hai."""
    idx = response.find(payload)
    if idx != -1:
        start = max(0, idx - 50)
        end   = min(len(response), idx + window)
        return response[start:end].strip()
    return "Payload reflected in response"
