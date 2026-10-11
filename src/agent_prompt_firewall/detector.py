"""
detector.py - Heuristic, Entropy, and Pattern-Based Threat Detection Engine.
Zero external dependencies (Python 3.10+ standard library).
"""

import base64
import binascii
import math
import re
import unicodedata
from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Any


def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts: Dict[str, int] = {}
    for char in data:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def normalize_for_matching(text: str) -> str:
    """Defeat cheap evasions before pattern matching: NFKC folds full-width and
    compatibility letters to ASCII, and invisible format characters (zero-width
    space/joiners, soft hyphen, bidi controls, BOM) are removed."""
    folded = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in folded if unicodedata.category(ch) != "Cf")


# --- Attack Signatures & Heuristic Rules ---

DIRECT_OVERRIDE_PATTERNS = [
    (r"(?i)\b(ignore|disregard|forget|override|skip|drop)\s+(all\s+)?(of\s+)?(the\s+|your\s+|my\s+|these\s+|those\s+|any\s+)?(previous|prior|above|earlier|preceding|original)\s+(instructions|directives|prompts|rules|guidelines|messages|commands)", "Direct Instruction Override", 0.95),
    (r"(?i)\bsystem\s+override\b", "System Override Directive", 0.95),
    (r"(?i)\b(dan\s+mode|developer\s+mode\s+enabled|unrestricted\s+mode)\b", "Jailbreak Mode Activation", 0.95),
    (r"(?i)\bdisregard\s+(all\s+)?(prior|previous|existing)\s+(guidelines|constraints|safety)", "Constraint Disregard Attack", 0.90),
    (r"(?i)\byou\s+are\s+now\s+(freed|unconstrained|unfiltered|jailbroken)\b", "Roleplay Boundary Removal", 0.90),
    (r"(?i)\bbypass\s+(all\s+)?(safety|ethical|content)\s+(filters|protocols|boundaries)", "Safety Filter Bypass", 0.92),
    (r"(?i)\bdo\s+anything\s+now\b", "DAN Persona Trigger", 0.90),
    (r"(?i)\bpretend\s+you\s+have\s+no\s+(rules|guidelines|instructions)", "Rule Negation Roleplay", 0.85),
    (r"(?i)\bact\s+as\s+(an\s+evil|an\s+unhinged|an\s+unfiltered)\b", "Adversarial Persona Injection", 0.88),
]

EXFILTRATION_PATTERNS = [
    (r"(?i)\b(repeat|print|echo|show|dump|reveal|output)\s+(your\s+)?(system\s+prompt|initial\s+prompt|hidden\s+instructions|core\s+directives)", "System Prompt Exfiltration", 0.95),
    (r"(?i)\bwhat\s+(are|were)\s+the\s+(exact\s+)?(instructions|directives|words)\s+(given\s+to\s+you|above|before)", "Context Leakage Probe", 0.88),
    (r"(?i)\bbegin\s+your\s+response\s+with\s+(the\s+words\s+)?['\"]?(system:|system prompt)", "Header Hijack Probe", 0.85),
    (r"(?i)!\[.*?\]\((https?:\/\/[^\s\)]+[\?&](leak|exfil|data|prompt)=[^\s\)]*)\)", "Markdown Image Exfiltration", 0.95),
    (r"(?i)\btranscribe\s+(everything|the\s+text)\s+from\s+the\s+system\s+block", "System Block Extraction", 0.90),
]

DELIMITER_PATTERNS = [
    (r"\[/?INST\]", "Llama/Mistral Instruction Delimiter Injection", 0.92),
    (r"<\|im_start\|>|<\|im_end\|>", "ChatML Delimiter Hijack", 0.95),
    (r"```(system|prompt|assistant|human|developer)", "Markdown Role Hijack", 0.88),
    (r"<\/?system>|<\/?user>|<\/?assistant>", "Pseudo-XML Tag Injection", 0.85),
    (r"\[SYS\]|\[\/SYS\]|\[SYSTEM\]", "System Marker Injection", 0.90),
    (r"<<SYS>>|<\/SYS>", "Llama-2 System Delimiter Hijack", 0.92),
]

OBFUSCATION_PATTERNS = [
    (r"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", "Base64 High-Density Blob", 0.70),
    (r"(?:\\x[0-9a-fA-F]{2}){8,}", "Hex Escape Sequence Injection", 0.80),
    (r"(?:&#x?[0-9a-fA-F]+;\s*){6,}", "HTML Entity Obfuscation", 0.80),
]


@dataclass
class ThreatAssessment:
    score: float
    threat_type: str
    categories: List[str] = field(default_factory=list)
    details: List[str] = field(default_factory=list)
    should_block: bool = False
    entropy: float = 0.0
    obfuscation_detected: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 3),
            "threat_type": self.threat_type,
            "categories": self.categories,
            "details": self.details,
            "should_block": self.should_block,
            "entropy": self.entropy,
            "obfuscation_detected": self.obfuscation_detected,
        }


class ThreatDetector:
    """Prompt injection, delimiter collision, and obfuscation detection engine."""

    def __init__(self, block_threshold: float = 0.75):
        self.block_threshold = block_threshold

    def _inspect_decoded_string(self, text: str) -> List[Tuple[str, str, float]]:
        findings = []
        text = normalize_for_matching(text)
        for pattern, desc, weight in DELIMITER_PATTERNS:
            if re.search(pattern, text):
                findings.append(("DELIMITER_INJECTION", f"Decoded payload contains: {desc}", weight))
        for pattern, desc, weight in DIRECT_OVERRIDE_PATTERNS:
            if re.search(pattern, text):
                findings.append(("DIRECT_OVERRIDE", f"Decoded payload contains: {desc}", weight))
        for pattern, desc, weight in EXFILTRATION_PATTERNS:
            if re.search(pattern, text):
                findings.append(("EXFILTRATION", f"Decoded payload contains: {desc}", weight))
        return findings

    def evaluate(self, prompt: str) -> ThreatAssessment:
        if not prompt or not prompt.strip():
            return ThreatAssessment(score=0.0, threat_type="CLEAN", details=["Empty or whitespace prompt"])

        max_weight = 0.0
        categories: List[str] = []
        details: List[str] = []
        obfuscation_flag = False

        raw_prompt = prompt
        prompt = normalize_for_matching(raw_prompt)
        if prompt != unicodedata.normalize("NFKC", raw_prompt):
            hidden = len(unicodedata.normalize("NFKC", raw_prompt)) - len(prompt)
            details.append(f"Stripped {hidden} invisible format character(s) before inspection")
            obfuscation_flag = True
            max_weight = max(max_weight, 0.30)

        # 1. Direct Override Patterns
        for pattern, desc, weight in DIRECT_OVERRIDE_PATTERNS:
            match = re.search(pattern, prompt)
            if match:
                max_weight = max(max_weight, weight)
                if "DIRECT_OVERRIDE" not in categories:
                    categories.append("DIRECT_OVERRIDE")
                details.append(f"{desc}: '{match.group(0)[:60]}'")

        # 2. System Prompt Exfiltration
        for pattern, desc, weight in EXFILTRATION_PATTERNS:
            match = re.search(pattern, prompt)
            if match:
                max_weight = max(max_weight, weight)
                if "EXFILTRATION" not in categories:
                    categories.append("EXFILTRATION")
                details.append(f"{desc}: '{match.group(0)[:60]}'")

        # 3. Delimiter Injection
        for pattern, desc, weight in DELIMITER_PATTERNS:
            match = re.search(pattern, prompt)
            if match:
                max_weight = max(max_weight, weight)
                if "DELIMITER_INJECTION" not in categories:
                    categories.append("DELIMITER_INJECTION")
                details.append(f"{desc}: '{match.group(0)[:40]}'")

        # 4. Obfuscation & Base64 / Hex Inspection
        b64_matches = re.findall(r"(?:[A-Za-z0-9+/]{4}){7,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", prompt)
        for b64 in b64_matches:
            try:
                decoded_bytes = base64.b64decode(b64, validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                decoded_findings = self._inspect_decoded_string(decoded_str)
                if decoded_findings:
                    obfuscation_flag = True
                    for cat, d_desc, d_weight in decoded_findings:
                        max_weight = max(max_weight, min(1.0, d_weight + 0.05))
                        if cat not in categories:
                            categories.append(cat)
                        details.append(f"Base64 Obfuscated Attack ({d_desc})")
                elif len(b64) > 64 and shannon_entropy(b64) > 4.5:
                    obfuscation_flag = True
                    details.append(f"High-entropy Base64 sequence detected ({len(b64)} chars)")
                    max_weight = max(max_weight, 0.45)
            except Exception:
                pass

        # Hex patterns
        hex_matches = re.findall(r"(?:\\x[0-9a-fA-F]{2}){6,}", prompt)
        for hx in hex_matches:
            try:
                raw_hex = hx.replace("\\x", "")
                decoded = bytes.fromhex(raw_hex).decode("utf-8", errors="ignore")
                decoded_findings = self._inspect_decoded_string(decoded)
                if decoded_findings:
                    obfuscation_flag = True
                    for cat, d_desc, d_weight in decoded_findings:
                        max_weight = max(max_weight, min(1.0, d_weight + 0.05))
                        if cat not in categories:
                            categories.append(cat)
                        details.append(f"Hex Obfuscated Attack ({d_desc})")
                else:
                    obfuscation_flag = True
                    details.append(f"Hex byte escape sequence detected ({len(hx)} chars)")
                    max_weight = max(max_weight, 0.50)
            except Exception:
                pass

        # 5. Shannon Entropy Calculation
        overall_entropy = shannon_entropy(raw_prompt)
        if overall_entropy > 5.2 and len(prompt) > 80:
            if not obfuscation_flag and "OBFUSCATION" not in categories:
                categories.append("OBFUSCATION")
            details.append(f"High Shannon entropy ({overall_entropy:.2f} bits/symbol)")
            max_weight = max(max_weight, 0.40)

        # Threat classification
        if max_weight >= 0.85:
            threat_type = "CRITICAL"
        elif max_weight >= 0.70:
            threat_type = "HIGH"
        elif max_weight >= 0.45:
            threat_type = "MEDIUM"
        elif max_weight >= 0.20:
            threat_type = "LOW"
        else:
            threat_type = "CLEAN"

        should_block = max_weight >= self.block_threshold

        return ThreatAssessment(
            score=max_weight,
            threat_type=threat_type,
            categories=categories,
            details=details,
            should_block=should_block,
            entropy=overall_entropy,
            obfuscation_detected=obfuscation_flag,
        )
