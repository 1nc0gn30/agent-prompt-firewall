"""
detector.py - Heuristic, Entropy, De-obfuscation, and Pattern-Based Threat Detection Engine.
Zero external dependencies (Python 3.10+ standard library).
Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform
"""

import base64
import codecs
import html
import math
import re
import unicodedata
import urllib.parse
import zlib
from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Any, Optional


# Cyrillic & Greek confusable homoglyph folding table (lookalike -> Latin ASCII)
_HOMOGLYPH_MAP = str.maketrans({
    # Cyrillic lowercase
    "\u0430": "a",  # а
    "\u0432": "b",  # в
    "\u0441": "c",  # с
    "\u0435": "e",  # е
    "\u0451": "e",  # ё
    "\u0456": "i",  # і
    "\u0458": "j",  # ј
    "\u043a": "k",  # к
    "\u043c": "m",  # м
    "\u043d": "h",  # н
    "\u043e": "o",  # о
    "\u0440": "p",  # р
    "\u0455": "s",  # ѕ
    "\u0442": "t",  # т
    "\u0443": "y",  # у
    "\u0445": "x",  # х
    "\u0447": "y",  # ч
    "\u0433": "r",  # г
    "\u04bb": "h",  # һ
    "\u0501": "d",  # ԁ
    "\u051b": "q",  # ԛ
    "\u051d": "w",  # ԝ
    # Cyrillic uppercase
    "\u0410": "A",  # А
    "\u0412": "B",  # В
    "\u0421": "C",  # С
    "\u0415": "E",  # Е
    "\u041d": "H",  # Н
    "\u0406": "I",  # І
    "\u0408": "J",  # Ј
    "\u041a": "K",  # К
    "\u041c": "M",  # М
    "\u041e": "O",  # О
    "\u0420": "P",  # Р
    "\u0405": "S",  # Ѕ
    "\u0422": "T",  # Т
    "\u0425": "X",  # Х
    "\u0423": "Y",  # У
    # Greek lowercase
    "\u03b1": "a",  # α
    "\u03b2": "b",  # β
    "\u03b5": "e",  # ε
    "\u03b9": "i",  # ι
    "\u03ba": "k",  # κ
    "\u03bd": "v",  # ν
    "\u03bf": "o",  # ο
    "\u03c1": "p",  # ρ
    "\u03c4": "t",  # τ
    "\u03c5": "u",  # υ
    "\u03c7": "x",  # χ
    # Greek uppercase
    "\u0391": "A",  # Α
    "\u0392": "B",  # Β
    "\u0395": "E",  # Ε
    "\u0396": "Z",  # Ζ
    "\u0397": "H",  # Η
    "\u0399": "I",  # Ι
    "\u039a": "K",  # Κ
    "\u039c": "M",  # Μ
    "\u039d": "N",  # Ν
    "\u039f": "O",  # Ο
    "\u03a1": "P",  # Ρ
    "\u03a4": "T",  # Τ
    "\u03a5": "Y",  # Υ
    "\u03a7": "X",  # Χ
})

_LEET_MAP_I = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
    "!": "i",
})

_LEET_MAP_L = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
    "!": "i",
})

_JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")


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


def fold_homoglyphs(text: str) -> str:
    """Fold Cyrillic/Greek confusable homoglyphs to Latin ASCII equivalents."""
    return text.translate(_HOMOGLYPH_MAP)


def normalize_for_matching(text: str) -> str:
    """Defeat cheap evasions before pattern matching: NFKC folds full-width and
    compatibility letters to ASCII, invisible format characters (zero-width
    space/joiners, soft hyphen, bidi controls, BOM) are removed, and Cyrillic/Greek
    homoglyphs are folded to Latin ASCII."""
    folded = unicodedata.normalize("NFKC", text)
    stripped = "".join(ch for ch in folded if unicodedata.category(ch) != "Cf")
    return fold_homoglyphs(stripped)


def _normalize_leetspeak_variants(text: str) -> List[str]:
    """Produce leetspeak-decoded variants when mixed alphanumeric/symbol words exist."""
    if not re.search(r"(?:[A-Za-z][013457@$!]|[013457@$!][A-Za-z])", text):
        return []
    # Translate only tokens that contain at least one letter + leet digit/symbol
    def _sub_word(table):
        def repl(m):
            tok = m.group(0)
            if re.search(r"[A-Za-z]", tok) and re.search(r"[013457@$!]", tok):
                return tok.translate(table)
            return tok
        return re.sub(r"[A-Za-z0-9@$!]+", repl, text)

    v1 = _sub_word(_LEET_MAP_I)
    v2 = _sub_word(_LEET_MAP_L)
    # Also handle common "a11" -> "all" + "1gnore" -> "ignore" hybrid
    v3 = re.sub(r"\b([aA])11\b", r"\1ll", v1)
    variants = []
    for v in (v1, v2, v3):
        if v != text and v not in variants:
            variants.append(v)
    return variants


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
    """Prompt injection, delimiter collision, and multi-layer de-obfuscation engine."""

    def __init__(self, block_threshold: float = 0.70):
        self.block_threshold = block_threshold

    def _inspect_decoded_string(self, text: str) -> List[Tuple[str, str, float]]:
        findings: List[Tuple[str, str, float]] = []
        norm = normalize_for_matching(text)
        for pattern, desc, weight in DELIMITER_PATTERNS:
            if re.search(pattern, norm):
                findings.append(("DELIMITER_INJECTION", f"Decoded payload contains: {desc}", weight))
        for pattern, desc, weight in DIRECT_OVERRIDE_PATTERNS:
            if re.search(pattern, norm):
                findings.append(("DIRECT_OVERRIDE", f"Decoded payload contains: {desc}", weight))
        for pattern, desc, weight in EXFILTRATION_PATTERNS:
            if re.search(pattern, norm):
                findings.append(("EXFILTRATION", f"Decoded payload contains: {desc}", weight))
        return findings

    def _try_decode_base64_and_zlib(self, token: str) -> List[str]:
        decoded_texts: List[str] = []
        try:
            raw_bytes = base64.b64decode(token, validate=True)
        except Exception:
            return decoded_texts

        # Try plain UTF-8
        utf8_text = raw_bytes.decode("utf-8", errors="ignore")
        if utf8_text:
            decoded_texts.append(utf8_text)

        # Try zlib-compressed payload (capped to 64 KiB against zip bombs)
        if len(raw_bytes) >= 2 and raw_bytes[0] == 0x78 and raw_bytes[1] in (0x01, 0x5E, 0x9C, 0xDA):
            try:
                decomp = zlib.decompressobj().decompress(raw_bytes, 65536)
                z_text = decomp.decode("utf-8", errors="ignore")
                if z_text:
                    decoded_texts.append(z_text)
            except Exception:
                pass
        return decoded_texts

    def evaluate(self, prompt: str, threshold: Optional[float] = None) -> ThreatAssessment:
        if not prompt or not prompt.strip():
            return ThreatAssessment(score=0.0, threat_type="CLEAN", details=["Empty or whitespace prompt"])

        effective_threshold = self.block_threshold if threshold is None else float(threshold)
        max_weight = 0.0
        categories: List[str] = []
        details: List[str] = []
        obfuscation_flag = False

        raw_prompt = prompt
        nfkc_prompt = unicodedata.normalize("NFKC", raw_prompt)
        stripped_prompt = "".join(ch for ch in nfkc_prompt if unicodedata.category(ch) != "Cf")
        prompt = fold_homoglyphs(stripped_prompt)

        if stripped_prompt != nfkc_prompt:
            hidden = len(nfkc_prompt) - len(stripped_prompt)
            details.append(f"Stripped {hidden} invisible format character(s) before inspection")
            obfuscation_flag = True
            max_weight = max(max_weight, 0.30)

        homoglyphs_folded = (prompt != stripped_prompt)

        # 1. Direct Override Patterns
        for pattern, desc, weight in DIRECT_OVERRIDE_PATTERNS:
            match = re.search(pattern, prompt)
            if match:
                max_weight = max(max_weight, weight)
                if "DIRECT_OVERRIDE" not in categories:
                    categories.append("DIRECT_OVERRIDE")
                prefix = "Homoglyph-Obfuscated " if homoglyphs_folded else ""
                if homoglyphs_folded:
                    obfuscation_flag = True
                details.append(f"{prefix}{desc}: '{match.group(0)[:60]}'")

        # 2. System Prompt Exfiltration
        for pattern, desc, weight in EXFILTRATION_PATTERNS:
            match = re.search(pattern, prompt)
            if match:
                max_weight = max(max_weight, weight)
                if "EXFILTRATION" not in categories:
                    categories.append("EXFILTRATION")
                prefix = "Homoglyph-Obfuscated " if homoglyphs_folded else ""
                if homoglyphs_folded:
                    obfuscation_flag = True
                details.append(f"{prefix}{desc}: '{match.group(0)[:60]}'")

        # 3. Delimiter Injection
        for pattern, desc, weight in DELIMITER_PATTERNS:
            match = re.search(pattern, prompt)
            if match:
                max_weight = max(max_weight, weight)
                if "DELIMITER_INJECTION" not in categories:
                    categories.append("DELIMITER_INJECTION")
                prefix = "Homoglyph-Obfuscated " if homoglyphs_folded else ""
                if homoglyphs_folded:
                    obfuscation_flag = True
                details.append(f"{prefix}{desc}: '{match.group(0)[:40]}'")

        # 4a. HTML Entity Decoding (e.g. &#105;&#103;&#110;... or &lt;|im_start|&gt;)
        if "&" in prompt and (";" in prompt):
            unescaped = html.unescape(prompt)
            if unescaped != prompt:
                entity_findings = self._inspect_decoded_string(unescaped)
                if entity_findings:
                    obfuscation_flag = True
                    for cat, d_desc, d_weight in entity_findings:
                        max_weight = max(max_weight, min(1.0, d_weight + 0.03))
                        if cat not in categories:
                            categories.append(cat)
                        details.append(f"HTML Entity Obfuscated Attack ({d_desc})")

        # 4b. URL Percent-Decoding (single & double pass)
        if "%" in prompt and re.search(r"%[0-9a-fA-F]{2}", prompt):
            unquoted = urllib.parse.unquote(prompt)
            if "%" in unquoted and re.search(r"%[0-9a-fA-F]{2}", unquoted):
                unquoted = urllib.parse.unquote(unquoted)
            if unquoted != prompt:
                url_findings = self._inspect_decoded_string(unquoted)
                if url_findings:
                    obfuscation_flag = True
                    for cat, d_desc, d_weight in url_findings:
                        max_weight = max(max_weight, min(1.0, d_weight + 0.03))
                        if cat not in categories:
                            categories.append(cat)
                        details.append(f"URL-Encoded Obfuscated Attack ({d_desc})")

        # 4c. ROT13 Decoding
        rot13_text = codecs.decode(prompt, "rot_13")
        rot_findings = self._inspect_decoded_string(rot13_text)
        if rot_findings:
            obfuscation_flag = True
            for cat, d_desc, d_weight in rot_findings:
                max_weight = max(max_weight, min(1.0, d_weight + 0.03))
                if cat not in categories:
                    categories.append(cat)
                details.append(f"ROT13 Obfuscated Attack ({d_desc})")

        # 4d. Leetspeak Normalization (report only newly uncovered categories not already matched in plain text)
        for leet_variant in _normalize_leetspeak_variants(prompt):
            leet_findings = [f for f in self._inspect_decoded_string(leet_variant) if f[0] not in categories]
            if leet_findings:
                obfuscation_flag = True
                for cat, d_desc, d_weight in leet_findings:
                    max_weight = max(max_weight, min(1.0, d_weight + 0.02))
                    if cat not in categories:
                        categories.append(cat)
                    details.append(f"Leetspeak Obfuscated Attack ({d_desc})")
                break

        # 4e. Base64 & Zlib Inspection (skip benign standard JWT tokens unless they decode to an attack)
        jwt_spans = [m.span() for m in _JWT_PATTERN.finditer(prompt)]

        def _in_jwt(start: int, end: int) -> bool:
            return any(js <= start and end <= je for js, je in jwt_spans)

        for m in re.finditer(r"(?:[A-Za-z0-9+/]{4}){7,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", prompt):
            b64 = m.group(0)
            decoded_candidates = self._try_decode_base64_and_zlib(b64)
            found_attack = False
            for decoded_str in decoded_candidates:
                decoded_findings = self._inspect_decoded_string(decoded_str)
                if decoded_findings:
                    found_attack = True
                    obfuscation_flag = True
                    for cat, d_desc, d_weight in decoded_findings:
                        max_weight = max(max_weight, min(1.0, d_weight + 0.05))
                        if cat not in categories:
                            categories.append(cat)
                        details.append(f"Base64 Obfuscated Attack ({d_desc})")
            if not found_attack and not _in_jwt(m.start(), m.end()) and len(b64) > 64 and shannon_entropy(b64) > 4.5:
                obfuscation_flag = True
                details.append(f"High-entropy Base64 sequence detected ({len(b64)} chars)")
                max_weight = max(max_weight, 0.45)

        # 4f. Hex Escape Sequence Inspection
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

        # 5. Shannon Entropy Calculation (ignore entropy spikes caused solely by benign JWTs)
        entropy_target = _JWT_PATTERN.sub("", raw_prompt).strip() or raw_prompt
        overall_entropy = shannon_entropy(raw_prompt)
        non_jwt_entropy = shannon_entropy(entropy_target)
        if non_jwt_entropy > 5.2 and len(entropy_target) > 80:
            if not obfuscation_flag and "OBFUSCATION" not in categories:
                categories.append("OBFUSCATION")
            details.append(f"High Shannon entropy ({non_jwt_entropy:.2f} bits/symbol)")
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

        should_block = max_weight >= effective_threshold

        return ThreatAssessment(
            score=max_weight,
            threat_type=threat_type,
            categories=categories,
            details=details,
            should_block=should_block,
            entropy=overall_entropy,
            obfuscation_detected=obfuscation_flag,
        )
