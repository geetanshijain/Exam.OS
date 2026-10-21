import json
import logging
import random
from typing import Any

from app.studio.ai_adapter import get_ai_provider, wrap_untrusted_input
from app.studio.validator import check_duplicate_risk, compute_jaccard_similarity, validate_question

logger = logging.getLogger(__name__)

ACADEMIC_QUESTION_TEMPLATES = {
    "short_answer": {
        "easy": [
            "Define the concept of {topic} in modern systems and state its primary purpose.",
            "State two fundamental advantages and limitations of {topic}.",
            "Differentiate briefly between {topic} and related traditional mechanisms.",
            "List the essential components comprising {topic}.",
            "What is {topic}? State its operational significance.",
        ],
        "medium": [
            "Explain the working principle of {topic} with a suitable real-world scenario.",
            "Compare and contrast {topic} with standard alternatives in computing.",
            "Describe how {topic} handles concurrency and edge-case exceptions.",
        ],
        "hard": [
            "Analyze the trade-offs involved in configuring {topic} for high-throughput environments.",
        ],
    },
    "descriptive": {
        "easy": [
            "Describe the overall architecture and functional pipeline of {topic} with a schematic diagram.",
            "Discuss the lifecycle and phase transitions associated with {topic}.",
        ],
        "medium": [
            "Explain in detail the mechanism of {topic}. Discuss how it satisfies institutional performance criteria.",
            "Analyze the core algorithms governing {topic}. Illustrate step-by-step execution with a trace example.",
            "Differentiate between synchronous and asynchronous handling in {topic}, highlighting security trade-offs.",
        ],
        "hard": [
            "Design a robust, scalable system architecture incorporating {topic}. Evaluate potential failure modes and propose mitigation strategies.",
            "Critically analyze the performance bottlenecks of {topic} under extreme load. Derive the theoretical complexity and propose an optimization scheme.",
            "Evaluate the architectural resilience of {topic} against unauthorized state modifications and concurrency race conditions.",
        ],
    },
    "numerical": {
        "easy": [
            "Calculate the throughput for a system utilizing {topic} given standard baseline parameters.",
        ],
        "medium": [
            "Given an arrival rate of 120 requests/sec and service rate of 150 requests/sec in {topic}, compute the utilization factor and average queue delay.",
            "Solve for the memory overhead and fragmentation percentage when applying {topic} across an 8GB partition.",
        ],
        "hard": [
            "Derive the expected latency and fault recovery time for {topic} operating across a three-node cluster with 99.9% availability constraints.",
        ],
    },
    "mcq": {
        "easy": [
            "Which of the following best defines the primary characteristic of {topic}?\n(a) High latency\n(b) Deterministic state consistency\n(c) Uncontrolled concurrency\n(d) Volatile storage",
            "In the context of {topic}, which component is directly responsible for interface mediation?\n(a) Dispatcher\n(b) Controller\n(c) Buffer cache\n(d) Register",
        ],
        "medium": [
            "When {topic} experiences a deadlock hazard, which strategy provides non-preemptive recovery?\n(a) Resource ordering\n(b) Arbitrary termination\n(c) Infinite spinlock\n(d) Memory paging",
        ],
        "hard": [
            "Under peak concurrency, which invariant must hold true for {topic} to guarantee linearizability?\n(a) Strict sequential ordering\n(b) Eventual convergence\n(c) Unsynchronized caching\n(d) Optimistic locking without validation",
        ],
    },
}


def build_default_blueprint(total_marks: int = 100) -> dict[str, Any]:
    """Generates an institutionally aligned blueprint based on standard examination structures."""
    if total_marks <= 50:
        return {
            "sections": [
                {"section_name": "Part A (Short Answer)", "question_type": "short_answer", "marks_per_question": 2, "count": 5, "difficulty": "easy"},
                {"section_name": "Part B (Analytical)", "question_type": "descriptive", "marks_per_question": 8, "count": 5, "difficulty": "medium"},
            ]
        }
    return {
        "sections": [
            {"section_name": "Part A (Foundation & Definitions)", "question_type": "short_answer", "marks_per_question": 2, "count": 10, "difficulty": "easy"},
            {"section_name": "Part B (Core Descriptive & Analytical)", "question_type": "descriptive", "marks_per_question": 10, "count": 5, "difficulty": "medium"},
            {"section_name": "Part C (Comprehensive Design / Case Study)", "question_type": "descriptive", "marks_per_question": 15, "count": 2, "difficulty": "hard"},
        ]
    }


def generate_blueprint_questions(
    blueprint: dict[str, Any],
    units: list[dict[str, Any]],
    learning_outcomes: list[dict[str, str]],
    historical_questions: list[str],
    allow_external_ai: bool = False,
) -> list[dict[str, Any]]:
    """
    Generates new questions adhering strictly to the examination blueprint,
    syllabus weightings, and learning outcomes.
    
    Guarantees:
    - Zero external data transmission unless allow_external_ai=True.
    - Explicit AI suggestion disclaimer (non-guarantee).
    - Near-duplicate detection against historical and concurrent questions.
    - Validation checks against syllabus and ambiguity.
    """
    generated: list[dict[str, Any]] = []
    sections = blueprint.get("sections", [])
    
    if not sections:
        sections = build_default_blueprint().get("sections", [])

    # Extract all topic names for validation
    all_syllabus_topic_names = []
    for u in units:
        for t in u.get("topics", []):
            all_syllabus_topic_names.append(t.get("name", ""))
            all_syllabus_topic_names.extend(t.get("subtopics", []))

    lo_codes = [lo.get("code", f"CO{i+1}") for i, lo in enumerate(learning_outcomes)] if learning_outcomes else ["CO1", "CO2", "CO3", "CO4", "CO5"]

    # Flat reference list of questions to detect duplicate questions in-flight
    all_reference_questions = list(historical_questions)

    unit_index = 0
    total_units = max(len(units), 1)

    for section in sections:
        sec_name = section.get("section_name", "Section")
        q_type = section.get("question_type", "descriptive")
        marks = section.get("marks_per_question", 10)
        count = section.get("count", 1)
        difficulty = section.get("difficulty", "medium")

        for _ in range(count):
            # Rotate across syllabus units
            assigned_unit = units[unit_index % total_units] if units else {
                "unit_number": 1,
                "title": "General Core Concepts",
                "topics": [{"name": "Core Principles", "subtopics": []}],
                "source_page": 1,
            }
            unit_index += 1

            # Pick a topic from the unit
            topics_list = assigned_unit.get("topics", [])
            chosen_topic_dict = random.choice(topics_list) if topics_list else {"name": assigned_unit.get("title", "Core Unit"), "subtopics": []}
            topic_name = chosen_topic_dict.get("name", "Core Concept")

            # Pick matching LO code
            assigned_lo = lo_codes[(assigned_unit.get("unit_number", 1) - 1) % len(lo_codes)]

            # Select template
            type_templates = ACADEMIC_QUESTION_TEMPLATES.get(q_type, ACADEMIC_QUESTION_TEMPLATES["descriptive"])
            diff_templates = type_templates.get(difficulty, type_templates["medium"])
            template = random.choice(diff_templates)

            q_text = template.format(topic=topic_name)

            # Generate expected answer points rubric
            subtopics = chosen_topic_dict.get("subtopics", [])
            expected_points = [
                f"1. Accurate conceptual definition of {topic_name} and institutional terminology.",
                f"2. Comprehensive explanation of key operational mechanisms ({', '.join(subtopics[:2]) or 'architectural structure'}).",
                f"3. Practical application, system state analysis, or diagrammatic representation.",
                f"4. Discussion of failure modes, performance trade-offs, and security implications.",
            ]

            # Compute duplicate risk against historical and already generated
            dup_score, matched_dup_q = check_duplicate_risk(q_text, all_reference_questions)

            # Run validation checks
            validation_flags = validate_question(
                question_text=q_text,
                syllabus_topics=all_syllabus_topic_names,
                marks=marks,
                question_type=q_type,
                learning_outcomes=learning_outcomes,
            )

            if dup_score >= 0.65:
                validation_flags.append(f"NEAR_DUPLICATE_FLAG: {int(dup_score * 100)}% token similarity to existing question.")

            # Record question
            provenance = (
                f"Derived from Syllabus Unit {assigned_unit.get('unit_number')}: '{assigned_unit.get('title')}' "
                f"(Topic: '{topic_name}', Source Page: {assigned_unit.get('source_page', 1)}). "
                f"Designed for Bloom's Level: {difficulty.upper()} under Outcome {assigned_lo}."
            )

            question_obj = {
                "question_text": q_text,
                "marks": marks,
                "question_type": q_type,
                "difficulty": difficulty,
                "unit_number": assigned_unit.get("unit_number", 1),
                "syllabus_topic": topic_name,
                "learning_outcome_code": assigned_lo,
                "expected_answer_points": expected_points,
                "provenance_basis": provenance,
                "duplicate_risk_score": round(dup_score, 3),
                "validation_flags": validation_flags,
                "review_status": "draft_suggestion",
                "reviewer_comments": None,
                "is_ai_suggestion": True,
                "disclaimer": "AI-generated suggestion. Requires mandatory exam setter review and verification.",
            }

            generated.append(question_obj)
            all_reference_questions.append(q_text)

    return generated
