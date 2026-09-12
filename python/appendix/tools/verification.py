"""Verification-plan semantics shared by the builder, checker, and authoring tools.

Test IDs are stable within an operation. postcondition_index identifies one entry in
expected_postconditions. These cross-references require semantic checks beyond JSON Schema.
"""
INDEPENDENT = {"read_system_of_record", "independent_observation", "human_confirmation"}


def verification_errors(plan: dict, tests_key: str = "tests") -> list[str]:
    """Return fail-closed errors without evaluating any claimed observation."""
    if not isinstance(plan, dict):
        return ["verification plan must be an object"]
    tests = plan.get(tests_key, [])
    postconditions = plan.get("expected_postconditions", [])
    if not isinstance(tests, list) or not isinstance(postconditions, list):
        return ["verification tests and postconditions must be arrays"]
    errors, ids, covered = [], set(), set()
    independent_ids = set()
    for test in tests:
        if not isinstance(test, dict):
            errors.append("verification test must be an object")
            continue
        tid = test.get("test_id")
        if not isinstance(tid, str) or not tid:
            errors.append("verification test needs a non-empty test_id")
        elif tid in ids:
            errors.append(f"duplicate test_id: {tid}")
        else:
            ids.add(tid)
        if test.get("method") in INDEPENDENT:
            index = test.get("postcondition_index")
            if type(index) is not int or not 0 <= index < len(postconditions):
                errors.append(f"{tid}: postcondition_index does not reference an expected postcondition")
            else:
                covered.add(index)
            if isinstance(tid, str):
                independent_ids.add(tid)
            if not isinstance(test.get("source"), str) or not test["source"]:
                errors.append(f"{tid}: independent test needs a source")
    rule = plan.get("completion_rule", "all_postconditions_verified")
    designated = plan.get("designated_test_ids", [])
    if rule == "all_postconditions_verified":
        if designated:
            errors.append("all_postconditions_verified must not designate a subset")
        if set(range(len(postconditions))) - covered:
            errors.append("all_postconditions_verified requires independent coverage of every expected postcondition")
        if not independent_ids:
            errors.append("all_postconditions_verified requires at least one independent test")
    elif rule == "designated_postconditions_verified":
        if not isinstance(designated, list) or not designated or any(not isinstance(x, str) for x in designated):
            errors.append("designated_postconditions_verified needs non-empty designated_test_ids")
        elif len(set(designated)) != len(designated) or not set(designated).issubset(independent_ids):
            errors.append("designated_test_ids must be unique, known, independent test IDs")
    else:
        errors.append("unknown completion_rule")
    age = plan.get("max_observation_age_seconds")
    if type(age) is not int or age < 1:
        errors.append("max_observation_age_seconds must be a positive integer")
    return errors


def required_test_ids(plan: dict, tests_key: str = "verification_tests") -> set[str]:
    """Caller must validate the plan first. Tool receipts never define completion."""
    if plan["completion_rule"] == "designated_postconditions_verified":
        return set(plan["designated_test_ids"])
    return {t["test_id"] for t in plan[tests_key] if t["method"] in INDEPENDENT}


def render_template(template: str, request: dict) -> str:
    """Use the same deterministic placeholder expansion at construction and containment."""
    class Safe(dict):
        def __missing__(self, key):
            return "{" + key + "}"
    values = Safe(**(request.get("parameters") or {}))
    target, subject = request["effect_target"], request.get("subject") or {}
    values.update({"effect_target": target.get("display") or target["identifier"],
                   "effect_target_id": target["identifier"],
                   "subject": subject.get("display") or subject.get("identifier", "")})
    return template.format_map(values)


def render_verification_plan(plan: dict, request: dict) -> dict:
    """Derive the whole plan; callers cannot silently weaken completion or freshness."""
    return {
        "expected_postconditions": [render_template(p, request) for p in plan.get("expected_postconditions", [])],
        "completion_rule": plan.get("completion_rule", "all_postconditions_verified"),
        "max_observation_age_seconds": plan.get("max_observation_age_seconds", 300),
        **({"designated_test_ids": list(plan["designated_test_ids"])} if "designated_test_ids" in plan else {}),
        "verification_tests": [{**t, "assertion": render_template(t["assertion"], request)} for t in plan.get("tests", [])],
        "on_failure": plan.get("on_failure", "escalate"),
    }
