import json
import re
from typing import Any


def parse_syllabus_structure(
    extracted_pages: list[dict[str, Any]],
    default_units: int = 5,
) -> dict[str, Any]:
    """
    Parses extracted syllabus text into structured units, topics, subtopics, and weightings.
    Preserves page provenance. Designed to handle diverse academic syllabus formats.
    """
    units: list[dict[str, Any]] = []
    
    # Unit header regex patterns (e.g., "UNIT 1", "Unit I", "Module 2", "Chapter 3", "Section A")
    unit_pattern = re.compile(
        r"^(?:unit|module|chapter|section)\s*([0-9]+|[ivxlcdm]+)[\s:.\-\u2013]+(.*)$",
        re.IGNORECASE,
    )
    
    current_unit: dict[str, Any] | None = None
    unit_counter = 0

    roman_to_int = {
        "i": 1, "ii": 2, "iii": 3, "iv": 4, "v": 5,
        "vi": 6, "vii": 7, "viii": 8, "ix": 9, "x": 10,
    }

    for page in extracted_pages:
        page_num = page.get("page_number", 1)
        page_text = page.get("text", "")
        lines = [line.strip() for line in page_text.splitlines() if line.strip()]

        for line in lines:
            match = unit_pattern.match(line)
            if match:
                # Save previous unit if exists
                if current_unit:
                    units.append(current_unit)

                unit_num_str = match.group(1).lower()
                unit_num = roman_to_int.get(unit_num_str)
                if unit_num is None:
                    try:
                        unit_num = int(unit_num_str)
                    except ValueError:
                        unit_counter += 1
                        unit_num = unit_counter
                else:
                    unit_counter = max(unit_counter, unit_num)

                unit_title = match.group(2).strip() or f"Unit {unit_num}"
                current_unit = {
                    "unit_number": unit_num,
                    "title": unit_title,
                    "weighting_percentage": 0.0,
                    "topics": [],
                    "source_page": page_num,
                }
            elif current_unit:
                # Parse topics / subtopics from line
                # Check for bullet or comma/semicolon separation
                clean_line = re.sub(r"^[\*\-\u2022\d\.\)]+\s*", "", line).strip()
                if clean_line and len(clean_line) > 3:
                    # If line has colon, e.g. "Topic: sub1, sub2"
                    if ":" in clean_line:
                        parts = clean_line.split(":", 1)
                        topic_name = parts[0].strip()
                        subtopics = [s.strip() for s in re.split(r"[,;]", parts[1]) if s.strip()]
                        current_unit["topics"].append({
                            "name": topic_name,
                            "subtopics": subtopics,
                        })
                    else:
                        subtopics = [s.strip() for s in re.split(r"[,;]", clean_line) if s.strip()]
                        if len(subtopics) > 1:
                            current_unit["topics"].append({
                                "name": subtopics[0],
                                "subtopics": subtopics[1:],
                            })
                        else:
                            current_unit["topics"].append({
                                "name": clean_line,
                                "subtopics": [],
                            })

    if current_unit:
        units.append(current_unit)

    # Fallback if no unit markers were explicitly found in text
    if not units:
        # Group text into default units
        all_text = "\n".join(p.get("text", "") for p in extracted_pages)
        paragraphs = [p.strip() for p in all_text.split("\n\n") if len(p.strip()) > 20]
        
        num_units = min(max(len(paragraphs), 1), default_units)
        chunk_size = max(1, len(paragraphs) // num_units)

        for i in range(num_units):
            chunk = paragraphs[i * chunk_size : (i + 1) * chunk_size]
            sample_topics = []
            for p in chunk[:4]:
                first_sentence = p.split(".")[0].strip()[:80]
                if first_sentence:
                    sample_topics.append({"name": first_sentence, "subtopics": []})

            units.append({
                "unit_number": i + 1,
                "title": f"Syllabus Module {i + 1}",
                "weighting_percentage": round(100.0 / num_units, 2),
                "topics": sample_topics or [{"name": f"Module {i + 1} Core Concepts", "subtopics": []}],
                "source_page": 1,
            })

    # Distribute weightings evenly across identified units
    total_units = len(units)
    if total_units > 0:
        base_weight = round(100.0 / total_units, 2)
        for idx, u in enumerate(units):
            if idx == total_units - 1:
                # Balance rounding difference to exact 100%
                u["weighting_percentage"] = round(100.0 - (base_weight * (total_units - 1)), 2)
            else:
                u["weighting_percentage"] = base_weight

    return {
        "units": units,
        "total_units": len(units),
        "is_ai_parsed": True,
        "human_review_required": True,
    }


def validate_syllabus_structure(units: list[dict[str, Any]]) -> tuple[bool, str | None]:
    """
    Validates unit numbers and ensures weighting percentages sum to 100%.
    """
    if not units:
        return False, "Syllabus must contain at least one unit."

    total_weight = sum(float(u.get("weighting_percentage", 0.0)) for u in units)
    if not (99.0 <= total_weight <= 101.0):
        return False, f"Total syllabus unit weightings must sum to 100% (currently {total_weight}%)."

    for unit in units:
        if not unit.get("title"):
            return False, f"Unit {unit.get('unit_number', '?')} is missing a title."
        if not unit.get("topics"):
            return False, f"Unit '{unit.get('title')}' must contain at least one topic."

    return True, None
