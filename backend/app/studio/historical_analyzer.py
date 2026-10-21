import re
from typing import Any


BLOOM_TAXONOMY = {
    "easy": ["define", "list", "state", "name", "identify", "what is", "mention", "recall"],
    "medium": ["explain", "describe", "discuss", "compare", "differentiate", "distinguish", "illustrate", "calculate", "solve", "apply"],
    "hard": ["design", "evaluate", "analyze", "derive", "synthesize", "justify", "critique", "prove", "optimize"],
}


def estimate_difficulty(question_text: str) -> str:
    lower_text = question_text.lower()
    for verb in BLOOM_TAXONOMY["hard"]:
        if re.search(rf"\b{verb}\b", lower_text):
            return "hard"
    for verb in BLOOM_TAXONOMY["medium"]:
        if re.search(rf"\b{verb}\b", lower_text):
            return "medium"
    for verb in BLOOM_TAXONOMY["easy"]:
        if re.search(rf"\b{verb}\b", lower_text):
            return "easy"
    return "medium"


def detect_question_type(question_text: str) -> str:
    lower_text = question_text.lower()
    if re.search(r"\([a-d]\).*\([a-d]\)", lower_text, re.DOTALL) or re.search(r"a\).*\bb\).*\bc\)", lower_text):
        return "mcq"
    if any(k in lower_text for k in ["calculate", "compute", "solve", "find the value", "numerical"]):
        return "numerical"
    if any(k in lower_text for k in ["define", "what is", "list two", "state the", "short note"]):
        return "short_answer"
    return "descriptive"


def extract_marks(line: str) -> int:
    """Extracts marks annotated in question line like [10], (5 Marks), [15M]."""
    marks_match = re.search(r"(?:\[|\()(\d+)\s*(?:marks?|m)?(?:\]|\))", line, re.IGNORECASE)
    if marks_match:
        try:
            return int(marks_match.group(1))
        except ValueError:
            pass
    return 10  # default academic mark


def extract_historical_questions_from_pages(
    extracted_pages: list[dict[str, Any]],
    doc_id: int | None = None,
) -> list[dict[str, Any]]:
    """
    Parses extracted document pages to isolate individual past exam questions
    along with their page provenance, estimated marks, difficulty, and type.
    """
    questions: list[dict[str, Any]] = []
    
    # Question delimiter pattern e.g. "Q1.", "Q. 2", "1.", "Question 3:"
    q_split_pattern = re.compile(
        r"(?:^|\n)\s*(?:q(?:uestion)?\.?\s*\d+|\d+)\s*[\.\:\)]\s*",
        re.IGNORECASE,
    )

    for page in extracted_pages:
        page_num = page.get("page_number", 1)
        page_text = page.get("text", "")
        
        # Split text into candidate question segments
        matches = list(q_split_pattern.finditer(page_text))
        if not matches:
            # Fallback: line by line with question marks
            lines = [l.strip() for l in page_text.splitlines() if l.strip()]
            for line in lines:
                if "?" in line or any(line.lower().startswith(v) for v in ["explain", "describe", "what", "define"]):
                    if len(line) > 15:
                        marks = extract_marks(line)
                        questions.append({
                            "question_text": line,
                            "marks": marks,
                            "question_type": detect_question_type(line),
                            "difficulty": estimate_difficulty(line),
                            "source_doc_id": doc_id,
                            "source_provenance": f"Page {page_num}",
                            "topics_detected": [],
                        })
            continue

        for idx, match in enumerate(matches):
            start = match.end()
            end = matches[idx + 1].start() if idx + 1 < len(matches) else len(page_text)
            segment = page_text[start:end].strip()
            
            # Clean up whitespace
            segment = re.sub(r"\s+", " ", segment)
            if len(segment) < 10:
                continue

            marks = extract_marks(segment)
            # Remove trailing marks tag from text if present
            clean_text = re.sub(r"(?:\[|\()\d+\s*(?:marks?|m)?(?:\]|\))", "", segment, flags=re.IGNORECASE).strip()

            questions.append({
                "question_text": clean_text or segment,
                "marks": marks,
                "question_type": detect_question_type(clean_text),
                "difficulty": estimate_difficulty(clean_text),
                "source_doc_id": doc_id,
                "source_provenance": f"Page {page_num}",
                "topics_detected": [],
            })

    return questions


def analyze_historical_coverage(
    historical_questions: list[dict[str, Any]],
    syllabus_units: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Analyzes historical questions against syllabus units:
    - Topic frequency & repetition
    - Question type distribution
    - Difficulty distribution
    - Unit coverage & blind spots
    """
    unit_counts: dict[int, int] = {u.get("unit_number", idx + 1): 0 for idx, u in enumerate(syllabus_units)}
    topic_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {"descriptive": 0, "short_answer": 0, "numerical": 0, "mcq": 0}
    difficulty_counts: dict[str, int] = {"easy": 0, "medium": 0, "hard": 0}
    repetition_clusters: list[dict[str, Any]] = []

    # Map keywords from syllabus
    for q in historical_questions:
        q_text = q.get("question_text", "").lower()
        matched_topics = []

        # Tally types and difficulty
        q_type = q.get("question_type", "descriptive")
        type_counts[q_type] = type_counts.get(q_type, 0) + 1

        q_diff = q.get("difficulty", "medium")
        difficulty_counts[q_diff] = difficulty_counts.get(q_diff, 0) + 1

        # Match syllabus units & topics
        for unit in syllabus_units:
            unit_num = unit.get("unit_number", 1)
            unit_matched = False

            for topic in unit.get("topics", []):
                topic_name = topic.get("name", "")
                if topic_name.lower() in q_text:
                    matched_topics.append(topic_name)
                    topic_counts[topic_name] = topic_counts.get(topic_name, 0) + 1
                    unit_matched = True

                for sub in topic.get("subtopics", []):
                    if sub.lower() in q_text:
                        matched_topics.append(f"{topic_name}: {sub}")
                        topic_counts[topic_name] = topic_counts.get(topic_name, 0) + 1
                        unit_matched = True

            if unit_matched:
                unit_counts[unit_num] = unit_counts.get(unit_num, 0) + 1

        q["topics_detected"] = matched_topics

    # Check for near-repetition among historical questions
    from app.studio.validator import compute_jaccard_similarity

    seen_pairs = set()
    for i, q1 in enumerate(historical_questions):
        for j, q2 in enumerate(historical_questions):
            if i < j and (i, j) not in seen_pairs:
                score = compute_jaccard_similarity(q1.get("question_text", ""), q2.get("question_text", ""))
                if score >= 0.65:
                    seen_pairs.add((i, j))
                    repetition_clusters.append({
                        "question_a": q1.get("question_text"),
                        "provenance_a": q1.get("source_provenance"),
                        "question_b": q2.get("question_text"),
                        "provenance_b": q2.get("source_provenance"),
                        "similarity_score": round(score, 3),
                    })

    total_q = max(len(historical_questions), 1)

    return {
        "total_historical_questions": len(historical_questions),
        "repetition_count": len(repetition_clusters),
        "repetition_clusters": repetition_clusters,
        "unit_coverage": unit_counts,
        "frequently_asked_topics": sorted(topic_counts.items(), key=lambda x: x[1], reverse=True)[:10],
        "type_distribution": {k: round((v / total_q) * 100, 1) for k, v in type_counts.items()},
        "difficulty_distribution": {k: round((v / total_q) * 100, 1) for k, v in difficulty_counts.items()},
    }
