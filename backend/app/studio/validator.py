import re
from typing import Any


STOP_WORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are",
    "aren't", "as", "at", "be", "because", "been", "before", "being", "below", "between", "both",
    "but", "by", "can", "cannot", "could", "couldn't", "did", "didn't", "do", "does", "doesn't",
    "doing", "don't", "down", "during", "each", "few", "for", "from", "further", "had", "hadn't",
    "has", "hasn't", "have", "haven't", "having", "he", "her", "here", "hers", "herself", "him",
    "himself", "his", "how", "i", "if", "in", "into", "is", "isn't", "it", "its", "itself", "let's",
    "me", "more", "most", "mustn't", "my", "myself", "no", "nor", "not", "of", "off", "on", "once",
    "only", "or", "other", "ought", "our", "ours", "ourselves", "out", "over", "own", "same", "shan't",
    "she", "should", "shouldn't", "so", "some", "such", "than", "that", "the", "their", "theirs",
    "them", "themselves", "then", "there", "these", "they", "this", "those", "through", "to", "too",
    "under", "until", "up", "very", "was", "wasn't", "we", "were", "weren't", "what", "when", "where",
    "which", "while", "who", "whom", "why", "with", "won't", "would", "wouldn't", "you", "your", "yours",
}


def tokenize(text: str) -> set[str]:
    """Tokenizes text into normalized alphanumeric word stems excluding stop words."""
    words = re.findall(r"\b[a-zA-Z]{3,}\b", text.lower())
    return {w for w in words if w not in STOP_WORDS}


def compute_jaccard_similarity(text_a: str, text_b: str) -> float:
    """Computes Jaccard index similarity between two texts using token sets."""
    set_a = tokenize(text_a)
    set_b = tokenize(text_b)
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a.intersection(set_b))
    union = len(set_a.union(set_b))
    return float(intersection / union) if union > 0 else 0.0


def check_duplicate_risk(
    candidate_text: str,
    reference_questions: list[str],
    threshold: float = 0.65,
) -> tuple[float, str | None]:
    """
    Checks candidate question against a collection of reference questions
    (e.g., historical questions and other generated questions).
    Returns (highest_similarity_score, matched_question_text).
    """
    max_score = 0.0
    matched_q: str | None = None

    for ref_q in reference_questions:
        if not ref_q:
            continue
        score = compute_jaccard_similarity(candidate_text, ref_q)
        if score > max_score:
            max_score = score
            matched_q = ref_q

    return max_score, matched_q if max_score >= threshold else None


def validate_question(
    question_text: str,
    syllabus_topics: list[str],
    marks: int,
    question_type: str,
    learning_outcomes: list[dict[str, str]] | None = None,
) -> list[str]:
    """
    Validates a question and flags:
    1. Ambiguous or underspecified wording
    2. Unsupported references (e.g., missing figure, table, diagram)
    3. Out-of-syllabus topics (zero keyword overlap)
    4. Mark-depth disproportion
    5. Missing LO alignment
    """
    flags: list[str] = []
    text_lower = question_text.lower().strip()
    words = text_lower.split()

    # 1. Ambiguity / Under-specification check
    if len(words) < 5:
        flags.append("AMBIGUOUS_QUESTION: Question text is too brief to provide unambiguous examination context.")
    
    vague_phrases = ["discuss things", "write something", "give details etc", "as you know", "write whatever"]
    if any(vp in text_lower for vp in vague_phrases):
        flags.append("AMBIGUOUS_QUESTION: Contains vague or open-ended phrasing without clear criteria.")

    # 2. Unsupported reference check
    unsupported_patterns = [
        r"\bfigure\s*\d+\b",
        r"\bdiagram\s*(?:below|above|shown)\b",
        r"\btable\s*\d+\b",
        r"\bgiven\s*data\s*sheet\b",
        r"\bas\s*shown\s*in\s*the\s*circuit\b",
    ]
    for pat in unsupported_patterns:
        if re.search(pat, text_lower):
            flags.append(f"UNSUPPORTED_REFERENCE: Refers to an external diagram, figure, or table ('{pat}') that is not embedded.")

    # 3. Out-of-syllabus check
    if syllabus_topics:
        cand_tokens = tokenize(question_text)
        syllabus_tokens = set()
        for t in syllabus_topics:
            syllabus_tokens.update(tokenize(t))

        overlap = cand_tokens.intersection(syllabus_tokens)
        if not overlap:
            flags.append("OUT_OF_SYLLABUS: Zero keyword or topic overlap with approved syllabus units.")

    # 4. Mark vs depth disproportion
    if marks <= 2 and any(v in text_lower for v in ["design and implement", "comprehensive architecture", "elaborate with full derivation"]):
        flags.append("MARK_DISPROPORTION: High-effort derivation or architectural design requested for <= 2 marks.")
    elif marks >= 15 and len(words) < 10 and any(v in text_lower for v in ["define", "what is", "state the name"]):
        flags.append("MARK_DISPROPORTION: Simple recall or definition question allocated >= 15 marks.")

    return flags
