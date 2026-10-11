"""
redactor.py - Zero-Dependency PII & Secret Redaction Engine.
Scrubs API keys, private keys, database URLs, and personal identifiers.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple


def luhn_checksum(card_number_str: str) -> bool:
    """Validate a credit card number using the Luhn checksum formula."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 11 or len(digits) > 19:
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


SECRET_RULES: List[Tuple[str, str, str]] = [
    # (Category, Regex Pattern, Replacement Label)
    (
        "PRIVATE_KEY",
        r"-----BEGIN\s+(?:[A-Z0-9_-]+\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:[A-Z0-9_-]+\s+)?PRIVATE\s+KEY-----",
        "[REDACTED_PRIVATE_KEY]"
    ),
    (
        "API_KEY_ANTHROPIC",
        r"\bsk-ant-[a-zA-Z0-9_\-]{20,}\b",
        "[REDACTED_ANTHROPIC_KEY]"
    ),
    (
        "API_KEY_OPENAI",
        r"\b(?:sk-proj-|sk-admin-|sk-)[a-zA-Z0-9_\-]{24,}\b",
        "[REDACTED_OPENAI_KEY]"
    ),
    (
        "API_KEY_GOOGLE",
        r"\bAIzaSy[a-zA-Z0-9_\-]{33}\b",
        "[REDACTED_GOOGLE_API_KEY]"
    ),
    (
        "API_KEY_AWS",
        r"\bAKIA[0-9A-Z]{16}\b",
        "[REDACTED_AWS_ACCESS_KEY]"
    ),
    (
        "API_KEY_GITHUB",
        r"\bgh[pousr]_[0-9a-zA-Z]{36}\b",
        "[REDACTED_GITHUB_TOKEN]"
    ),
    (
        "API_KEY_STRIPE",
        r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b",
        "[REDACTED_STRIPE_KEY]"
    ),
    (
        "DATABASE_URL",
        r"\b(?:postgres|postgresql|mysql|mongodb|redis|amqp):\/\/[^\s:@]+:[^\s:@]+@[^\s\/]+(?:\/[^\s]*)?\b",
        "[REDACTED_DATABASE_URL]"
    ),
]

PII_RULES: List[Tuple[str, str, str]] = [
    (
        "SSN",
        r"\b\d{3}-\d{2}-\d{4}\b",
        "[REDACTED_SSN]"
    ),
    (
        "EMAIL",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "[REDACTED_EMAIL]"
    ),
    (
        "PHONE_NUMBER",
        r"(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b",
        "[REDACTED_PHONE]"
    ),
]

CC_CANDIDATE_REGEX = re.compile(r"\b(?:\d[ -]?){13,19}\b")


@dataclass
class RedactionResult:
    redacted_text: str
    redacted_count: int
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "redacted_text": self.redacted_text,
            "redacted_count": self.redacted_count,
            "findings": self.findings,
        }


class Redactor:
    """Zero-dependency sensitive data scrubber."""

    def __init__(self):
        pass

    def redact(self, text: str) -> RedactionResult:
        if not text:
            return RedactionResult(redacted_text="", redacted_count=0, findings=[])

        working_text = text
        findings: List[Dict[str, Any]] = []
        counts_by_type: Dict[str, int] = {}

        # 1. Scrub Secrets
        for token_type, pattern, placeholder in SECRET_RULES:
            matches = list(re.finditer(pattern, working_text))
            for match in reversed(matches):
                val = match.group(0)
                counts_by_type[token_type] = counts_by_type.get(token_type, 0) + 1
                token_placeholder = f"{placeholder[:-1]}_{counts_by_type[token_type]}]"
                masked_preview = val[:4] + "..." + val[-4:] if len(val) > 8 else "***"
                findings.append({
                    "type": token_type,
                    "placeholder": token_placeholder,
                    "preview": masked_preview,
                    "start": match.start(),
                    "end": match.end(),
                })
                working_text = working_text[:match.start()] + token_placeholder + working_text[match.end():]

        # 2. Scrub PII (Credit Cards with Luhn check)
        cc_matches = list(CC_CANDIDATE_REGEX.finditer(working_text))
        for match in reversed(cc_matches):
            raw_candidate = match.group(0)
            cleaned_digits = re.sub(r"[ -]", "", raw_candidate)
            if luhn_checksum(cleaned_digits):
                counts_by_type["CREDIT_CARD"] = counts_by_type.get("CREDIT_CARD", 0) + 1
                token_placeholder = f"[REDACTED_CREDIT_CARD_{counts_by_type['CREDIT_CARD']}]"
                findings.append({
                    "type": "CREDIT_CARD",
                    "placeholder": token_placeholder,
                    "preview": cleaned_digits[:4] + "-****-****-" + cleaned_digits[-4:],
                    "start": match.start(),
                    "end": match.end(),
                })
                working_text = working_text[:match.start()] + token_placeholder + working_text[match.end():]

        # 3. Scrub standard PII (Email, SSN, Phone)
        for token_type, pattern, placeholder in PII_RULES:
            matches = list(re.finditer(pattern, working_text))
            for match in reversed(matches):
                val = match.group(0)
                counts_by_type[token_type] = counts_by_type.get(token_type, 0) + 1
                token_placeholder = f"{placeholder[:-1]}_{counts_by_type[token_type]}]"
                masked_preview = val[:2] + "***" + val[-2:] if len(val) > 4 else "***"
                findings.append({
                    "type": token_type,
                    "placeholder": token_placeholder,
                    "preview": masked_preview,
                    "start": match.start(),
                    "end": match.end(),
                })
                working_text = working_text[:match.start()] + token_placeholder + working_text[match.end():]

        return RedactionResult(
            redacted_text=working_text,
            redacted_count=len(findings),
            findings=findings,
        )
