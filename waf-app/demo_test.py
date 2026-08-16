#!/usr/bin/env python3
"""
demo_test.py

End-to-end demonstration script for the WAF project.
Sends a series of requests (normal and attack payloads) to a base URL
and prints a pass/fail summary table.

Usage:
    python demo_test.py [base_url]

If no base_url is provided, defaults to http://localhost:5000.
"""

import sys
import requests

# Try to import colorama for colored output; fallback to plain text
try:
    from colorama import init, Fore, Style
    init()
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    # Define dummy Fore/Style classes so the code doesn't crash without colorama
    class Fore:
        GREEN = ''
        RED = ''
    class Style:
        RESET_ALL = ''


def color_text(text, color):
    """Wrap text with color if colorama is available."""
    if HAS_COLOR:
        return f"{color}{text}{Style.RESET_ALL}"
    return text


def print_header():
    """Print the test summary table header."""
    print("=" * 80)
    print("WAF DEMO TEST SUITE")
    print("=" * 80)
    print(f"{'Test':<25} {'Payload':<35} {'Expected':<10} {'Actual':<10} {'Result'}")
    print("-" * 80)


def print_result(test_name, payload, expected, actual, passed):
    """Print a single test result row."""
    result = color_text("PASS", Fore.GREEN) if passed else color_text("FAIL", Fore.RED)
    print(f"{test_name:<25} {payload:<35} {expected:<10} {actual:<10} {result}")


def run_test(name, method, url, **kwargs):
    """
    Send a request and return (status_code, passed).
    expected_status is passed via kwargs.
    """
    expected = kwargs.pop("expected", None)
    try:
        if method.upper() == "GET":
            resp = requests.get(url, timeout=5, **kwargs)
        elif method.upper() == "POST":
            resp = requests.post(url, timeout=5, **kwargs)
        else:
            return None, False
        actual = resp.status_code
        passed = (actual == expected)
        return actual, passed
    except Exception as e:
        print(f"Error during request to {url}: {e}")
        return None, False


def main():
    # Determine base URL
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    # Ensure base_url ends without trailing slash for clean joins
    if base_url.endswith("/"):
        base_url = base_url[:-1]

    print(f"Target base URL: {base_url}\n")

    # List of tests: (name, payload, method, path, expected_status)
    tests = [
        ("Normal Home", "/", "GET", "/", 200),
        ("Normal Search", "q=laptop", "GET", "/search", 200),
        ("SQL Injection", "q=' OR '1'='1", "GET", "/search", 403),
        ("XSS", "q=<script>alert(1)</script>", "GET", "/search", 403),
        ("Directory Traversal", "q=../../../etc/passwd", "GET", "/search", 403),
        ("Command Injection", "q=; cat /etc/passwd", "GET", "/search", 403),
    ]

    passed_count = 0
    failed_count = 0
    print_header()

    # Execute individual tests
    for name, payload, method, path, expected in tests:
        if method == "GET":
            url = f"{base_url}{path}?{payload}" if payload else f"{base_url}{path}"
        else:
            url = f"{base_url}{path}"
        actual, passed = run_test(name, method, url, expected=expected)
        if passed:
            passed_count += 1
        else:
            failed_count += 1
        print_result(name, payload if payload else "-", expected, actual, passed)

    # Rate limit burst test
    burst_name = "Rate Limit Burst"
    burst_payload = "25 rapid GET /"
    expected_burst = ">=1 429"
    actual_429_count = 0
    try:
        for _ in range(25):
            resp = requests.get(f"{base_url}/", timeout=5)
            if resp.status_code == 429:
                actual_429_count += 1
        passed_burst = actual_429_count >= 1
    except Exception as e:
        print(f"Error during burst: {e}")
        passed_burst = False

    if passed_burst:
        passed_count += 1
    else:
        failed_count += 1
    print_result(burst_name, burst_payload, expected_burst, f"{actual_429_count} x 429", passed_burst)

    # Summary
    print("-" * 80)
    total = passed_count + failed_count
    print(f"Total tests: {total}")
    print(color_text(f"Passed: {passed_count}", Fore.GREEN))
    print(color_text(f"Failed: {failed_count}", Fore.RED))
    print("=" * 80)


if __name__ == "__main__":
    main()