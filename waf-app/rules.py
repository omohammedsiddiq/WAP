# rules.py
"""
Rule-based detection engine for a Web Application Firewall (WAF).

This module provides functions to detect common web attack patterns in
incoming HTTP requests. The detection is performed on normalized text
(URL-decoded and lowercased) to counter evasion attempts that use
percent-encoding, double-encoding, mixed case, or other obfuscation
techniques.

Attack categories covered:
  1. SQL Injection (SQLi)
  2. Cross-Site Scripting (XSS)
  3. Directory Traversal
  4. Command Injection
"""

import re
import json
import urllib.parse

# ----------------------------------------------------------------------
# Regex pattern lists for each attack category.
# Each pattern is a raw string; we use re.IGNORECASE during matching.
# Patterns are intentionally simple and may be extended easily.
# ----------------------------------------------------------------------

SQLI_PATTERNS = [
    # Classic always-true condition: ' OR '1'='1
    r"'\s*or\s+'1'\s*=\s*'1",
    # Generic always-true: 1=1, 'x'='x', etc.
    r"\b\d+\s*=\s*\d+\b",
    # UNION SELECT: used to combine results from multiple queries
    r"union\s+select",
    # SQL comment sequence: --
    r"--",
    # Inline comment after a semicolon: ;--
    r";\s*--",
    # Block comment start: /*
    r"/\*",
    # Block comment end: */
    r"\*/",
    # DROP TABLE: destructive command
    r"drop\s+table",
    # SELECT ... FROM: basic query pattern
    r"\bselect\b.*\bfrom\b",
    # Common SQL injection keywords
    r"\b(?:insert\s+into|update\s+\w+\s+set|delete\s+from)\b",
]

XSS_PATTERNS = [
    # <script> tag opening
    r"<\s*script\b[^>]*>",
    # Event handler attribute: onerror=
    r"onerror\s*=",
    # Event handler attribute: onload=
    r"onload\s*=",
    # javascript: protocol
    r"javascript\s*:",
    # <img> with src and onerror
    r"<\s*img[^>]+src\s*=[^>]*onerror\s*=",
    # <svg> with onload
    r"<\s*svg[^>]*onload\s*=",
    # <iframe> with javascript: src
    r"<\s*iframe[^>]+src\s*=\s*['\"]?javascript:",
    # Other common event handlers
    r"onmouseover\s*=",
    # document.cookie access
    r"document\.cookie",
    # alert() call
    r"\balert\s*\(",
]

TRAVERSAL_PATTERNS = [
    # Relative path with forward slash: ../
    r"\.\./",
    # Relative path with backslash: ..\
    r"\.\.\\",
    # URL-encoded dot-dot-slash: %2e%2e%2f (caught after decoding, but kept as extra)
    r"%2e%2e%2f",
    # URL-encoded dot-dot backslash: %2e%2e%5c
    r"%2e%2e%5c",
    # Attempt to access /etc/passwd (Unix password file)
    r"/etc/passwd",
    # Attempt to access Windows system files
    r"\b(?:boot\.ini|win\.ini|system32)\b",
    # Double dot with mixed encoding: %2e%2e (decoded to ..)
    r"%2e%2e",
    # Absolute path traversal: /../../
    r"/\.\./",
    # Backslash absolute path
    r"\\\\",
    # Path containing ".." with no slash
    r"\b\.\.\b",
]

COMMAND_INJECTION_PATTERNS = [
    # Semicolon followed by common command: ; ls, ; cat, ; whoami
    r";\s*(?:ls|cat|pwd|whoami|id|wget|curl|bash|sh|cmd|powershell)\b",
    # Pipe followed by command: | cat, | whoami
    r"\|\s*(?:ls|cat|whoami|id)\b",
    # Double ampersand followed by command: && whoami
    r"&&\s*(?:ls|whoami|id)\b",
    # Backtick command substitution: `...`
    r"`[^`]+`",
    # Dollar-parentheses command substitution: $(...)
    r"\$\([^)]+\)",
    # Command with shell meta-character and common binary
    r"\b(?:ping|nslookup|wget|curl)\s+[^;|&]+[;|&]",
    # Explicit shell invocation with -c option
    r"\b(?:bash|sh|cmd|powershell)\s+-c\b",
    # Newline or carriage return followed by command
    r"[\r\n]+\s*(?:ls|cat|whoami|id)\b",
]

# ----------------------------------------------------------------------
# Helper function to test a string against a list of regex patterns.
# Returns the matching pattern (string) if any pattern matches, else None.
# ----------------------------------------------------------------------
def _check_patterns(text, patterns):
    """
    Check if the given text contains any pattern from the list.

    Args:
        text (str): The text to inspect.
        patterns (list): List of regex pattern strings.

    Returns:
        str or None: The first pattern that matches, or None if no match.
    """
    if not text:
        return None
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return pattern
    return None


# ----------------------------------------------------------------------
# Individual detection functions (return True/False)
# ----------------------------------------------------------------------
def detect_sqli(text):
    """Return True if the text appears to contain SQL injection."""
    return _check_patterns(text, SQLI_PATTERNS) is not None


def detect_xss(text):
    """Return True if the text appears to contain XSS."""
    return _check_patterns(text, XSS_PATTERNS) is not None


def detect_traversal(text):
    """Return True if the text appears to contain directory traversal."""
    return _check_patterns(text, TRAVERSAL_PATTERNS) is not None


def detect_command_injection(text):
    """Return True if the text appears to contain command injection."""
    return _check_patterns(text, COMMAND_INJECTION_PATTERNS) is not None


# ----------------------------------------------------------------------
# Master function that inspects an entire request_data dictionary.
# ----------------------------------------------------------------------
def check_request(request_data):
    """
    Analyze all relevant parts of a captured request and determine if it
    contains any attack patterns.

    The function:
      1. Extracts text from URL, path, query parameters, headers (excluding
         standard ones), cookies, and body (raw, form, JSON).
      2. Normalizes each text by URL-decoding and lowercasing.
      3. Checks each normalized text against the pattern lists for SQLi,
         XSS, directory traversal, and command injection.
      4. Returns a dict with:
           - is_attack: True if any attack pattern is found
           - attack_type: the category of the first matched attack
           - matched_pattern: the specific regex pattern that matched

    Args:
        request_data (dict): Dictionary containing request information as
                             extracted by the WAF proxy.

    Returns:
        dict: Result as described above.
    """
    # ---------------------------
    # 1. Extract all text fields
    # ---------------------------
    texts = []

    # Full URL and path
    texts.append(request_data.get('full_url', ''))
    texts.append(request_data.get('path', ''))

    # Query parameters: keys and values
    query_params = request_data.get('query_params', {})
    for key, values in query_params.items():
        texts.append(key)
        if isinstance(values, list):
            texts.extend(values)
        else:
            texts.append(str(values))

    # Headers: exclude common browser headers to reduce noise
    EXCLUDED_HEADERS = {
        'user-agent', 'accept', 'accept-language', 'accept-encoding',
        'connection', 'cache-control', 'upgrade-insecure-requests',
        'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site',
        'sec-fetch-user', 'pragma', 'referer', 'host',
        'content-length', 'content-type', 'cookie'
    }
    headers = request_data.get('headers', {})
    for header_name, header_value in headers.items():
        if header_name.lower() not in EXCLUDED_HEADERS:
            # Store both header name and value
            texts.append(f"{header_name}: {header_value}")

    # Cookies: keys and values
    cookies = request_data.get('cookies', {})
    for cookie_name, cookie_value in cookies.items():
        texts.append(cookie_name)
        texts.append(cookie_value)

    # Raw body
    texts.append(request_data.get('raw_body', ''))

    # Form data (application/x-www-form-urlencoded)
    form_data = request_data.get('form_data', {})
    for key, values in form_data.items():
        texts.append(key)
        if isinstance(values, list):
            texts.extend(values)
        else:
            texts.append(str(values))

    # JSON data
    json_data = request_data.get('json_data')
    if json_data is not None:
        # Convert JSON object to string for pattern matching
        try:
            texts.append(json.dumps(json_data))
        except:
            texts.append(str(json_data))

    # ------------------------------------
    # 2. Normalize each text
    # ------------------------------------
    # Why normalization?
    # Attackers often encode malicious payloads to bypass simple string
    # matching. URL encoding (%27 for ', %3C for <), double encoding
    # (%2527), and mixed case are common evasion techniques.
    # By URL-decoding and lowercasing, we ensure that the detection engine
    # sees the true intended characters, making evasion harder.
    normalized_texts = []
    for text in texts:
        if isinstance(text, str):
            try:
                decoded = urllib.parse.unquote(text)  # decode %XX
            except:
                decoded = text
            normalized_texts.append(decoded.lower())
        else:
            normalized_texts.append(str(text).lower())

    # ------------------------------------------------------
    # 3. Check each category (in order) against all texts
    # ------------------------------------------------------
    categories = [
        ('sql_injection', SQLI_PATTERNS),
        ('xss', XSS_PATTERNS),
        ('directory_traversal', TRAVERSAL_PATTERNS),
        ('command_injection', COMMAND_INJECTION_PATTERNS),
    ]

    for attack_type, patterns in categories:
        for text in normalized_texts:
            matched = _check_patterns(text, patterns)
            if matched:
                # First match found
                return {
                    "is_attack": True,
                    "attack_type": attack_type,
                    "matched_pattern": matched
                }

    # --------------------------
    # 4. No attack detected
    # --------------------------
    return {
        "is_attack": False,
        "attack_type": None,
        "matched_pattern": None
    }