import logging
import re
from typing import Any

from app.schemas.assembly import PaperValidationReport, SectionRuleConfig
from app.studio.validator import compute_jaccard_similarity

logger = logging.getLogger(__name__)


def validate_assembled_paper(
    target_total_marks: int,
    sections: list[dict[str, Any]],
    mandatory_topics: list[str] | None = None,
    syllabus_units: list[dict[str, Any]] | None = None,
) -> PaperValidationReport:
    """
    Validates paper assembly according to institutional examination rules:
    1. Total marks match target marks (accounting for optional/internal choices)
    2. Mandatory topics are all assessed
    3. No duplicate or near-duplicate questions across the paper
    4. Valid section rules (e.g. questions_to_answer <= total questions, non-negative marks)
    5. Syllabus unit coverage
    """
    issues: list[str] = []
    total_paper_obtainable_marks = 0
    all_question_texts: list[str] = []
    covered_topics: set[str] = set()
    covered_units: set[int] = set()

    mandatory_topics = mandatory_topics or []
    normalized_mandatory = {t.strip().lower() for t in mandatory_topics if t.strip()}

    section_rules_valid = True
    total_marks_valid = True

    if not sections:
        issues.append("Paper contains no sections.")
        return PaperValidationReport(
            is_valid=False,
            total_marks_valid=False,
            mandatory_topics_covered=False,
            duplicate_check_passed=True,
            section_rules_valid=False,
            syllabus_coverage_valid=False,
            issues=issues,
        )

    for s_idx, sec in enumerate(sections):
        sec_name = sec.get("name", f"Section {s_idx + 1}")
        rule = sec.get("selection_rule", "all_compulsory")
        q_to_answer = sec.get("questions_to_answer", 0)
        marks_per_q = sec.get("marks_per_question", 0)
        configured_section_total = sec.get("total_section_marks", 0)
        questions = sec.get("questions", [])

        # 1. Validate section configuration
        expected_section_total = q_to_answer * marks_per_q
        if configured_section_total != expected_section_total:
            section_rules_valid = False
            issues.append(
                f"[{sec_name}] Section total marks mismatch: Configured as {configured_section_total}, "
                f"but {q_to_answer} questions * {marks_per_q} marks = {expected_section_total}."
            )

        if q_to_answer > len(questions):
            section_rules_valid = False
            issues.append(
                f"[{sec_name}] Invalid selection rule: Requires answering {q_to_answer} questions, "
                f"but only {len(questions)} question items are provided in the section."
            )

        total_paper_obtainable_marks += expected_section_total

        # 2. Extract question text, topics, units, and choices
        for q_item in questions:
            item_num = q_item.get("item_number", 0)
            has_internal_choice = q_item.get("has_internal_choice", False)
            choice_a = q_item.get("choice_a", {})
            choice_b = q_item.get("choice_b")

            # Choice A / Main question
            text_a = choice_a.get("question_text", "").strip()
            topic_a = choice_a.get("topic", "").strip()
            unit_a = choice_a.get("unit")
            marks_a = choice_a.get("marks", 0)

            if text_a:
                all_question_texts.append(text_a)
            if topic_a:
                covered_topics.add(topic_a.lower())
            if unit_a is not None:
                covered_units.add(unit_a)

            # Choice B (if internal choice)
            if has_internal_choice:
                if not choice_b:
                    section_rules_valid = False
                    issues.append(f"[{sec_name} Q{item_num}] Marked as internal choice but Choice B is missing.")
                else:
                    text_b = choice_b.get("question_text", "").strip()
                    topic_b = choice_b.get("topic", "").strip()
                    unit_b = choice_b.get("unit")
                    marks_b = choice_b.get("marks", 0)

                    if text_b:
                        all_question_texts.append(text_b)
                    if topic_b:
                        covered_topics.add(topic_b.lower())
                    if unit_b is not None:
                        covered_units.add(unit_b)

                    if marks_a != marks_b:
                        section_rules_valid = False
                        issues.append(
                            f"[{sec_name} Q{item_num}] Internal choice marks mismatch: "
                            f"Choice A carries {marks_a} marks while Choice B carries {marks_b} marks."
                        )

    # 3. Validate Total Marks
    if total_paper_obtainable_marks != target_total_marks:
        total_marks_valid = False
        issues.append(
            f"Paper total marks mismatch: Obtainable marks across all sections sum to "
            f"{total_paper_obtainable_marks}, but examination target is {target_total_marks} marks."
        )

    # 4. Validate Mandatory Topics
    mandatory_topics_covered = True
    missing_mandatory = []
    for orig_mt in mandatory_topics:
        mt = orig_mt.strip().lower()
        if not mt:
            continue
        matched = any(mt in ct or ct in mt for ct in covered_topics)
        if not matched:
            mandatory_topics_covered = False
            missing_mandatory.append(orig_mt.strip())

    if missing_mandatory:
        issues.append(
            f"Mandatory syllabus topic(s) not assessed in paper: {', '.join(missing_mandatory)}."
        )

    # 5. Duplicate Question Detection
    duplicate_check_passed = True
    seen_pairs = set()
    for i in range(len(all_question_texts)):
        for j in range(i + 1, len(all_question_texts)):
            pair = (i, j)
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                sim = compute_jaccard_similarity(all_question_texts[i], all_question_texts[j])
                if sim >= 0.65:
                    duplicate_check_passed = False
                    snippet_1 = all_question_texts[i][:45]
                    snippet_2 = all_question_texts[j][:45]
                    issues.append(
                        f"Near-duplicate question detected ({int(sim*100)}% similarity): "
                        f"'{snippet_1}...' matches '{snippet_2}...'"
                    )

    # 6. Syllabus Unit Coverage Check
    syllabus_coverage_valid = True
    if syllabus_units:
        required_units = {u.get("unit_number") for u in syllabus_units if u.get("unit_number")}
        missing_units = required_units - covered_units
        if missing_units:
            syllabus_coverage_valid = False
            issues.append(
                f"Syllabus coverage deficiency: Unit(s) {sorted(list(missing_units))} are not assessed in this paper."
            )

    is_overall_valid = (
        total_marks_valid
        and mandatory_topics_covered
        and duplicate_check_passed
        and section_rules_valid
        and syllabus_coverage_valid
    )

    return PaperValidationReport(
        is_valid=is_overall_valid,
        total_marks_valid=total_marks_valid,
        mandatory_topics_covered=mandatory_topics_covered,
        duplicate_check_passed=duplicate_check_passed,
        section_rules_valid=section_rules_valid,
        syllabus_coverage_valid=syllabus_coverage_valid,
        issues=issues,
    )
