"""
Project: Phishing Email Detection System Using Python
Author: Keya Mondal
Program: IBM SkillsBuild Cyber Security 2026 | BharatCares

Educational demonstration only. This is a rule-based screening tool,
not a production security product. A low score does not prove an email is safe.
"""

import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "verify your account", "urgent action", "account suspended",
    "password expires", "confirm your password", "login immediately",
    "click here", "update payment", "limited time", "claim your prize",
    "unusual activity", "security alert", "wire transfer", "gift card"
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "ow.ly", "buff.ly", "rb.gy"
}

URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+|www\.[^\s<>'\"]+", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)


def extract_urls(text):
    """Extract links from the supplied email text."""
    return URL_PATTERN.findall(text or "")


def normalise_url(raw_url):
    """Return a parsed URL and its host."""
    candidate = raw_url.strip().rstrip(".,);!?]")
    if candidate.lower().startswith("www."):
        candidate = "http://" + candidate
    parsed = urlparse(candidate)
    return candidate, (parsed.hostname or "").lower()


def analyse_email(email_text):
    """Flag selected phishing indicators using simple transparent rules."""
    text = (email_text or "").strip()
    lower_text = text.lower()
    findings = []
    score = 0

    matched_keywords = [word for word in SUSPICIOUS_KEYWORDS if word in lower_text]
    if matched_keywords:
        score += min(2 * len(matched_keywords), 6)
        findings.append("Urgent/account-related wording: " + ", ".join(matched_keywords))

    urls = extract_urls(text)
    if urls:
        findings.append(f"Found {len(urls)} link(s). Check the destination before opening.")

    for raw_url in urls:
        _, host = normalise_url(raw_url)
        if not host:
            score += 1
            findings.append(f"Could not clearly identify the host in link: {raw_url}")
            continue
        if host in URL_SHORTENERS:
            score += 3
            findings.append(f"URL shortener detected: {host}")
        if "@" in raw_url:
            score += 2
            findings.append(f"Link contains '@', which can confuse readers: {raw_url}")
        if host.startswith("xn--") or ".xn--" in host:
            score += 2
            findings.append(f"Internationalised/punycode domain needs checking: {host}")
        if host.count("-") >= 3:
            score += 1
            findings.append(f"Domain contains several hyphens: {host}")
        if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", host):
            score += 3
            findings.append(f"Link uses an IP address instead of a typical domain: {host}")

    if EMAIL_PATTERN.findall(text):
        findings.append("Email address found; verify the sender using a trusted channel.")

    if any(term in lower_text for term in ["password", "bank", "payment", "otp", "one-time code"]):
        score += 1
        findings.append("Sensitive information/payment topic mentioned; never share passwords or OTPs.")

    if not findings:
        findings.append("No obvious indicators were found by these simple rules.")

    if score >= 6:
        verdict = "HIGH RISK — treat as suspicious"
    elif score >= 3:
        verdict = "POTENTIALLY SUSPICIOUS — verify independently"
    else:
        verdict = "LOW INDICATOR SCORE — still use caution"

    return {"verdict": verdict, "indicator_score": score, "links_found": urls, "findings": findings}


def run_tests():
    """Run fictional examples to demonstrate the project."""
    test_messages = [
        "Hello, your meeting is confirmed for 3 PM. Regards, Team",
        "URGENT! Your account is suspended. Click here to verify your account: https://bit.ly/example",
        "Security alert: confirm your password and update payment immediately at http://192.168.1.10/login"
    ]
    print("\\nDEMONSTRATION TESTS")
    for number, message in enumerate(test_messages, start=1):
        result = analyse_email(message)
        print(f"\\nTest {number}: {message}")
        print("Verdict:", result["verdict"])
        print("Indicator score:", result["indicator_score"], "(not a probability)")
        for finding in result["findings"]:
            print("-", finding)


def main():
    print("=" * 60)
    print("PHISHING EMAIL DETECTION SYSTEM — EDUCATIONAL PROJECT")
    print("Author: Keya Mondal")
    print("=" * 60)
    print("This demo uses simple rules, not a trained AI model.")
    print("Use fictional sample text only. Do not enter private emails, passwords or OTPs.")
    run_tests()

    print("\\nTRY YOUR OWN FICTIONAL EMAIL")
    message = input("Enter email text: ")
    result = analyse_email(message)
    print("\\n--- ANALYSIS RESULT ---")
    print("Verdict:", result["verdict"])
    print("Indicator score:", result["indicator_score"], "(not a probability)")
    print("Links found:", result["links_found"] or "None")
    print("Findings:")
    for finding in result["findings"]:
        print("-", finding)
    print("\\nSafety reminder: verify suspicious requests using official contact details.")


if __name__ == "__main__":
    main()
