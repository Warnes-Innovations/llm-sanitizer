# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared featurizer for the semantic-intent classifier.

Used **identically** at train time (``scripts/train_semantic_intent.py``) and at
inference time (:mod:`llm_sanitizer.semantic.classifier`) — the two MUST agree
feature-for-feature or the vendored weights are meaningless, so there is exactly
one implementation and both import it from here.

Features are plain strings (binary presence, not counts):

* ``w:<token>``        — word unigram
* ``w2:<t1> <t2>``     — word bigram
* ``c:<n-gram>``       — character 3- and 4-grams within a boundary-padded token

Word n-grams carry the paraphrase signal; char n-grams add robustness to
morphological variants (persona/personas, verbatim/verbatim.) and light typos.
Binary presence (a ``set``) avoids length bias — a long benign document should
not out-score a short injection merely by repeating a token.

Pure stdlib: no numpy/sklearn, so the same code runs inside the scanner's
dependency-light install.
"""

from __future__ import annotations

import re

# Lowercased word tokens: letters/digits with internal apostrophes (don't, user's).
_TOKEN_RE = re.compile(r"[a-z0-9]+(?:'[a-z0-9]+)*")

# Character n-gram sizes. 3–4 balances coverage vs. model size; 2-grams explode
# the vocabulary with little added signal, 5+ overfit the corpus.
_CHAR_NGRAM_SIZES = (3, 4)

# Function-word stopwords excluded from word/char features. On a small corpus a
# linear model overfits these contentless tokens (e.g. "the" acquired a large
# spurious weight purely because it happened to be commoner in the negatives,
# then swamped real signal on short inputs). They carry no injection signal, and
# the phrase-level semantics they used to stand in for are now captured
# explicitly by the intent co-occurrence features below — so dropping them is
# pure denoising. Deliberately KEPT: temporal/self-referential cues that DO carry
# signal ("now", "above", "before", "you", "your").
_STOPWORDS = frozenset({
    "the", "a", "an", "of", "to", "and", "or", "is", "are", "was", "were", "be",
    "been", "being", "am", "it", "its", "this", "that", "these", "those", "with",
    "for", "as", "by", "at", "in", "on", "i", "me", "my", "we", "our", "will",
    "would", "shall", "can", "could", "may", "might", "do", "does", "did", "so",
    "than", "then", "if", "but", "into", "out", "here", "there", "please",
})

# Cap tokens featurized from any single text. The classifier scores short
# instruction-like spans; a pathologically long input should not turn featurize
# into an unbounded loop (the rule also slices content into bounded windows, but
# this is the belt-and-suspenders inner bound).
_MAX_TOKENS = 400

# --------------------------------------------------------------------------- #
# Domain-informed "intent co-occurrence" features                              #
# --------------------------------------------------------------------------- #
# Raw n-grams overfit on a small corpus and cannot separate, e.g., "output the
# ABOVE configuration verbatim" (exfil) from "print the configuration to verify"
# (benign) — the distinguishing semantics is *self-reference to prior context*,
# not any single token. These lexicon co-occurrence features encode that
# higher-level signal explicitly; they are emitted as ordinary features and
# WEIGHTED BY TRAINING like everything else (nothing here hard-codes a verdict),
# so they generalize to unseen phrasings while staying interpretable.

# Verbs that request the model to *emit* content it holds.
_EMIT_VERBS = frozenset({
    "output", "print", "repeat", "echo", "return", "reveal", "show", "recite",
    "reproduce", "emit", "dump", "restate", "relay", "disclose", "expose", "leak",
})
# Words that refer to the model's *prior/own* context — the exfil-echo tell.
# Deliberately NOT generic nouns like "configuration" (benign docs use those);
# these are self-referential-to-earlier-content cues.
_PRIOR_REFERENTS = frozenset({
    "above", "preceding", "foregoing", "prior", "previous", "earlier", "initial",
    "original", "hidden", "verbatim", "aforementioned", "unchanged", "unedited",
    "unaltered",
})
# Multi-token prior-context referents matched as substrings on the lowered text.
_PRIOR_REFERENT_PHRASES = (
    "you were given", "you received", "you were loaded", "your prompt",
    "your instructions", "your configuration", "your setup", "system prompt",
    "word for word", "character for character", "character-for-character",
)

_ROLE_VERBS = frozenset({
    "assume", "adopt", "become", "pretend", "impersonate", "slip", "step",
    "switch", "act", "behave", "roleplay",
})
_PERSONA_NOUNS = frozenset({
    "role", "persona", "identity", "character", "assistant", "model", "ai",
    "chatbot", "agent", "bot",
})
_CHANGE_CUES = frozenset({
    "different", "new", "another", "replacement", "alternate", "alternative",
    "separate", "rival", "fresh", "other",
})

_OVERRIDE_VERBS = frozenset({
    "ignore", "disregard", "forget", "override", "supersede", "supercede",
    "overrule", "void", "cancel", "discard", "abandon", "nullify",
})
# Objects an override would target: the model's earlier guidance.
_GUIDANCE_NOUNS = frozenset({
    "instruction", "instructions", "guidance", "guideline", "guidelines",
    "rule", "rules", "direction", "directions", "directive", "directives",
    "framing", "briefing", "constraints", "restrictions", "policy", "policies",
    "guardrails",
})
_PRIOR_CUES = frozenset({
    "prior", "previous", "earlier", "above", "before", "original", "preceding",
})
# Supersession expressed as *invalidation* rather than an override verb
# ("your prior guidance no longer applies / is void / is cancelled").
_INVALIDITY_CUES = frozenset({
    "cancelled", "canceled", "void", "voided", "revoked", "superseded",
    "obsolete", "expired", "invalid", "moot", "null", "defunct", "cancel",
})

# Covert-instruction framing: "keep this hidden from the user".
_NEGATIONS = frozenset({"not", "never", "dont", "don't", "without"})
_SILENCE_VERBS = frozenset({
    "tell", "mention", "reveal", "disclose", "inform", "say", "notify", "show",
})
_AUDIENCE = frozenset({
    "user", "anyone", "them", "person", "people", "nobody", "one", "human",
})

# Exfil-redirect: "send what you know to an external destination". The
# destination set is deliberately concrete (not the preposition "to", which is
# ubiquitous) so ordinary "send it to Bob" prose does not match.
_SEND_VERBS = frozenset({
    "send", "forward", "post", "upload", "transmit", "exfiltrate", "email",
    "leak", "relay",
})
_EXFIL_DESTINATIONS = frozenset({
    "external", "endpoint", "url", "server", "outside", "webhook", "http",
    "https", "attacker", "remote",
})


def _intent_features(tokens: set[str], text_lower: str) -> set[str]:
    """Higher-level co-occurrence features (see the block comment above)."""
    feats: set[str] = set()

    has_prior_ref = bool(tokens & _PRIOR_REFERENTS) or any(
        p in text_lower for p in _PRIOR_REFERENT_PHRASES
    )
    if tokens & _EMIT_VERBS and has_prior_ref:
        # "emit content + reference to prior/own context" = echo-exfil intent.
        feats.add("x:emit_prior_context")

    if tokens & _ROLE_VERBS and tokens & _PERSONA_NOUNS and tokens & _CHANGE_CUES:
        # "role verb + persona noun + change cue" = persona-reassignment intent.
        feats.add("x:role_reassignment")

    has_prior_guidance = bool(
        tokens & _GUIDANCE_NOUNS
        or tokens & _PRIOR_CUES
        or "you were told" in text_lower
        or "you were given" in text_lower
    )
    if tokens & _OVERRIDE_VERBS and has_prior_guidance:
        # "override verb + earlier-guidance object" = supersede-prior intent.
        feats.add("x:override_prior_guidance")
    elif has_prior_guidance and (tokens & _INVALIDITY_CUES or "no longer" in text_lower):
        # Same intent phrased as invalidation ("prior guidance no longer applies").
        feats.add("x:override_prior_guidance")

    if tokens & _NEGATIONS and tokens & _SILENCE_VERBS and tokens & _AUDIENCE:
        # "don't tell the user" = covert-instruction framing.
        feats.add("x:covert_instruction")

    if tokens & _SEND_VERBS and tokens & _EXFIL_DESTINATIONS:
        # "send/forward … to an external endpoint" = exfil-redirect intent.
        feats.add("x:exfil_redirect")

    return feats


# The structural-intent feature names, exposed so the detection rule can require
# at least one to be present as a precision gate (defense-in-depth): a span must
# both score above threshold AND exhibit a recognized injection structure to
# fire, so ordinary prose that merely trips n-gram noise cannot false-positive.
INTENT_FEATURES: frozenset[str] = frozenset({
    "x:emit_prior_context", "x:role_reassignment", "x:override_prior_guidance",
    "x:covert_instruction", "x:exfil_redirect",
})


def tokenize(text: str) -> list[str]:
    """Lowercase *text* and return its word tokens (bounded to _MAX_TOKENS)."""
    return _TOKEN_RE.findall(text.lower())[:_MAX_TOKENS]


def featurize(text: str) -> set[str]:
    """Return the set of presence features for *text* (see module docstring)."""
    tokens = tokenize(text)
    feats: set[str] = set()

    # Content tokens (stopwords dropped) drive the word/char n-grams; bigrams are
    # taken over the content stream so "output the above" → "output above" — a
    # skip-gram that survives filler words.
    content = [t for t in tokens if t not in _STOPWORDS]
    for i, tok in enumerate(content):
        feats.add(f"w:{tok}")
        if i + 1 < len(content):
            feats.add(f"w2:{tok} {content[i + 1]}")
        # Char n-grams over a boundary-padded token so prefixes/suffixes
        # ('<ver', 'tim>') become their own features.
        padded = f"<{tok}>"
        for n in _CHAR_NGRAM_SIZES:
            if len(padded) >= n:
                for j in range(len(padded) - n + 1):
                    feats.add(f"c:{padded[j:j + n]}")

    # Domain-informed intent co-occurrence features (weighted by training). These
    # use the FULL token set — the lexicons are content words, so filler tokens
    # are irrelevant to them.
    feats |= _intent_features(set(tokens), text.lower())
    return feats
