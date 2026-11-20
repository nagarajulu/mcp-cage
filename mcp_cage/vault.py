"""
`mcp_cage.vault` — Bidirectional Secret Scrubber, Destination-Bound FPE Vault,
Wire Payload Sanitizer, and Information-Theoretic Covert Channel Detectors.
"""

from __future__ import annotations

from mcp_cage.core import (
    AUTHORITY_LEXICON,
    BASE64_EXFIL_LABEL_RE,
    BidirectionalSecretScrubber,
    CANONICAL_UUID_RE,
    DestinationBoundFPEVault,
    ENGLISH_BIGRAMS,
    HEX_EXFIL_LABEL_RE,
    SENSITIVE_BAIT_LEXICON,
    WirePayloadSanitizer,
    bigram_transition_plausibility,
    is_covert_exfil_identifier,
    shannon_entropy,
)

__all__ = [
    "AUTHORITY_LEXICON",
    "BASE64_EXFIL_LABEL_RE",
    "BidirectionalSecretScrubber",
    "CANONICAL_UUID_RE",
    "DestinationBoundFPEVault",
    "ENGLISH_BIGRAMS",
    "HEX_EXFIL_LABEL_RE",
    "SENSITIVE_BAIT_LEXICON",
    "WirePayloadSanitizer",
    "bigram_transition_plausibility",
    "is_covert_exfil_identifier",
    "shannon_entropy",
]
