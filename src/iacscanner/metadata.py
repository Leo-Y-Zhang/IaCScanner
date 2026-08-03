"""Hand-curated triage metadata for every rule, in one reviewed place.

Each rule maps to one or more CWE weaknesses, one or more CIS Controls v8 controls, and a
default confidence (how certain a finding is, distinct from how severe it would be). The
registry attaches these onto the frozen Rule objects when it is assembled, so rules stay
declarative and the mapping stays a single source of truth (which SARIF and the reports
then surface). Confidence: literal, structural misconfigurations are HIGH; inference of a
missing control (or a broad regex) is MEDIUM.
"""
from __future__ import annotations

from iacscanner.models import Confidence

# rule_id -> (CWE ids, CIS Controls v8 controls, default confidence)
RULE_METADATA: dict[str, tuple[tuple[str, ...], tuple[str, ...], Confidence]] = {
    "TL001": (("CWE-284",), ("CIS Controls v8 Control 3",), Confidence.HIGH),
    "TL002": (("CWE-284",), ("CIS Controls v8 Control 3",), Confidence.MEDIUM),
    "TL003": (("CWE-269",), ("CIS Controls v8 Control 6",), Confidence.HIGH),
    "TL004": (("CWE-284",), ("CIS Controls v8 Control 6",), Confidence.HIGH),
    "TL005": (("CWE-284",), ("CIS Controls v8 Control 4",), Confidence.HIGH),
    "TL006": (("CWE-311",), ("CIS Controls v8 Control 3",), Confidence.HIGH),
    "TL007": (("CWE-311",), ("CIS Controls v8 Control 3",), Confidence.MEDIUM),
    "TL008": (("CWE-778",), ("CIS Controls v8 Control 8",), Confidence.MEDIUM),
    "TL009": (("CWE-778",), ("CIS Controls v8 Control 8",), Confidence.HIGH),
    "TL010": (("CWE-798",), ("CIS Controls v8 Control 3",), Confidence.HIGH),
    "TL011": (("CWE-250",), ("CIS Controls v8 Control 6",), Confidence.HIGH),
    "TL012": (("CWE-250",), ("CIS Controls v8 Control 6",), Confidence.MEDIUM),
    "TL013": (("CWE-668",), ("CIS Controls v8 Control 4",), Confidence.HIGH),
    "TL014": (("CWE-400",), ("CIS Controls v8 Control 4",), Confidence.MEDIUM),
    "TL015": (("CWE-1104",), ("CIS Controls v8 Control 4",), Confidence.MEDIUM),
    "TL016": (("CWE-94",), ("CIS Controls v8 Control 16",), Confidence.HIGH),
    "TL017": (("CWE-532",), ("CIS Controls v8 Control 8",), Confidence.HIGH),
    "TL018": (("CWE-798",), ("CIS Controls v8 Control 3",), Confidence.MEDIUM),
    "TL019": (("CWE-284",), ("CIS Controls v8 Control 4",), Confidence.HIGH),
    "TL020": (("CWE-320",), ("CIS Controls v8 Control 3",), Confidence.HIGH),
    "TL021": (("CWE-693",), ("CIS Controls v8 Control 7",), Confidence.HIGH),
    "TL022": (("CWE-311",), ("CIS Controls v8 Control 3",), Confidence.HIGH),
    "TL023": (("CWE-918",), ("CIS Controls v8 Control 4",), Confidence.HIGH),
    "TL024": (("CWE-693",), ("CIS Controls v8 Control 11",), Confidence.MEDIUM),
    "TL025": (("CWE-693",), ("CIS Controls v8 Control 11",), Confidence.MEDIUM),
    "TL026": (("CWE-250",), ("CIS Controls v8 Control 4",), Confidence.HIGH),
    "TL027": (("CWE-668",), ("CIS Controls v8 Control 4",), Confidence.HIGH),
    "TL028": (("CWE-829",), ("CIS Controls v8 Control 16",), Confidence.MEDIUM),
    "TL029": (("CWE-250",), ("CIS Controls v8 Control 4",), Confidence.HIGH),
    "TL030": (("CWE-798",), ("CIS Controls v8 Control 3",), Confidence.MEDIUM),
    "TL031": (("CWE-1104",), ("CIS Controls v8 Control 4",), Confidence.MEDIUM),
    "TL032": (("CWE-284",), ("CIS Controls v8 Control 4",), Confidence.HIGH),
}
