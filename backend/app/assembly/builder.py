import copy
import logging
import random
from typing import Any

from app.schemas.assembly import PaperBlueprintConfig, PaperQuestionItem, QuestionChoiceItem, SectionRuleConfig
from app.studio.generator import ACADEMIC_QUESTION_TEMPLATES

logger = logging.getLogger(__name__)

TOPIC_CATALOG = [
    "Process Synchronization and Semaphores",
    "Virtual Memory Paging and Segmentation",
    "Deadlock Avoidance and Bankers Algorithm",
    "File System Inodes and Journaling",
    "Distributed Consensus and Quorum Protocols",
    "CPU Scheduling and Multilevel Queues",
    "Memory Hierarchy and Translation Lookaside Buffers",
    "Device Drivers and Interrupt Handling",
    "Network Socket Communication",
    "Security Domains and Access Control Lists",
]


def assemble_paper_sections(
    blueprint: PaperBlueprintConfig,
    bank_questions: list[dict[str, Any]],
    seed: int | None = None,
) -> list[dict[str, Any]]:
    """
    Deterministically and reproducibly selects and organizes questions into
    structured sections with internal choices, adhering to blueprint rules.
    """
    rng = random.Random(seed) if seed is not None else random.Random()
    assembled_sections: list[dict[str, Any]] = []

    # Pool of candidate bank questions (copy so we can pop without mutating)
    available_pool = copy.deepcopy(bank_questions)
    
    # Sort/prioritize mandatory topics to the front of the pool
    mandatory_topics = [t.lower().strip() for t in blueprint.mandatory_topics if t.strip()]
    
    def _priority_key(bq: dict[str, Any]) -> int:
        top = bq.get("topic", "").lower()
        if any(mt in top or top in mt for mt in mandatory_topics):
            return 0  # Highest priority
        return 1

    available_pool.sort(key=_priority_key)

    global_item_counter = 1
    used_texts: set[str] = set()

    for s_idx, sec_cfg in enumerate(blueprint.sections):
        sec_dict = sec_cfg.model_dump()
        rule = sec_dict.get("selection_rule", "all_compulsory")
        q_to_answer = sec_dict.get("questions_to_answer", 1)
        marks_per_q = sec_dict.get("marks_per_question", 10)
        existing_questions = sec_dict.get("questions", [])

        # If questions are already explicitly provided in the blueprint, renumber and keep them
        if existing_questions and len(existing_questions) >= q_to_answer:
            formatted_qs = []
            for q_data in existing_questions:
                q_data["item_number"] = global_item_counter
                global_item_counter += 1
                formatted_qs.append(q_data)
            sec_dict["questions"] = formatted_qs
            assembled_sections.append(sec_dict)
            continue

        # Otherwise, dynamically assemble questions from bank pool
        assembled_sec_questions = []

        # Determine count of items needed
        if rule == "answer_n_of_m":
            total_items_to_provide = max(q_to_answer + 2, len(existing_questions))
        else:
            total_items_to_provide = q_to_answer

        for idx in range(total_items_to_provide):
            has_internal = (rule == "internal_choice")

            # 1. Select Choice A (or Main Question)
            choice_a = _pick_or_synthesize_question(
                available_pool=available_pool,
                target_marks=marks_per_q,
                target_type=_infer_type_for_marks(marks_per_q),
                target_diff=_infer_diff_for_marks(marks_per_q),
                rng=rng,
                default_unit=(global_item_counter % 5) + 1,
                used_texts=used_texts,
                mandatory_topic_hint=mandatory_topics[0] if (mandatory_topics and idx == 0) else None,
            )
            used_texts.add(choice_a["question_text"])

            # 2. Select Choice B if internal choice rule
            choice_b = None
            if has_internal:
                choice_b = _pick_or_synthesize_question(
                    available_pool=available_pool,
                    target_marks=marks_per_q,
                    target_type=choice_a.get("question_type", "descriptive"),
                    target_diff=choice_a.get("difficulty", "medium"),
                    rng=rng,
                    default_unit=((global_item_counter + 1) % 5) + 1,
                    used_texts=used_texts,
                )
                used_texts.add(choice_b["question_text"])

            question_item = {
                "item_number": global_item_counter,
                "has_internal_choice": has_internal,
                "marks": marks_per_q,
                "choice_a": choice_a,
                "choice_b": choice_b,
            }
            assembled_sec_questions.append(question_item)
            global_item_counter += 1

        sec_dict["questions"] = assembled_sec_questions
        sec_dict["total_section_marks"] = q_to_answer * marks_per_q
        assembled_sections.append(sec_dict)

    return assembled_sections


def _pick_or_synthesize_question(
    available_pool: list[dict[str, Any]],
    target_marks: int,
    target_type: str,
    target_diff: str,
    rng: random.Random,
    default_unit: int = 1,
    used_texts: set[str] | None = None,
    mandatory_topic_hint: str | None = None,
) -> dict[str, Any]:
    """Finds matching question from pool or deterministically synthesizes one."""
    used_texts = used_texts or set()

    # Look for exact marks match in bank that hasn't been used yet
    for idx, bq in enumerate(available_pool):
        if bq.get("marks") == target_marks and bq.get("question_text") not in used_texts:
            return available_pool.pop(idx)

    # If no exact marks match, look for any unused question
    for idx, bq in enumerate(available_pool):
        if bq.get("question_text") not in used_texts:
            candidate = available_pool.pop(idx)
            candidate["marks"] = target_marks
            return candidate

    # Cold start synthesis: generate reproducible question with distinct topic and template
    topic_name = mandatory_topic_hint.capitalize() if mandatory_topic_hint else TOPIC_CATALOG[rng.randint(0, len(TOPIC_CATALOG) - 1)]
    templates_by_type = ACADEMIC_QUESTION_TEMPLATES.get(target_type, ACADEMIC_QUESTION_TEMPLATES["descriptive"])
    templates = list(templates_by_type.get(target_diff, templates_by_type.get("medium", ["Explain {topic} in detail."])))
    rng.shuffle(templates)

    chosen_template = templates[0]
    for t in templates:
        candidate_text = t.format(topic=topic_name)
        if candidate_text not in used_texts:
            chosen_template = t
            break

    q_text = chosen_template.format(topic=topic_name)

    return {
        "question_id": None,
        "question_text": q_text,
        "marks": target_marks,
        "difficulty": target_diff,
        "question_type": target_type,
        "unit": default_unit,
        "topic": topic_name,
        "learning_outcome_code": f"CO{default_unit}",
        "expected_answer_points": [
            f"1. Clear academic definition of {topic_name}.",
            f"2. Methodological derivation or procedural analysis.",
            f"3. Practical context and system boundaries.",
        ],
        "source_provenance": "Paper Builder Deterministic Generator",
    }


def _infer_type_for_marks(marks: int) -> str:
    if marks <= 2:
        return "short_answer"
    return "descriptive"


def _infer_diff_for_marks(marks: int) -> str:
    if marks <= 2:
        return "easy"
    if marks <= 10:
        return "medium"
    return "hard"
