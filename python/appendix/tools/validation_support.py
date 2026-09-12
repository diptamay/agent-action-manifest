"""Required date/date-time schema validation, shared by gate, CLI and sign-offs.

Missing rfc3339-validator is a configuration error. The datetime parser deliberately
rejects leap seconds and requires an offset; gate clocks and evidence use the same subset.
"""
from jsonschema import FormatChecker
try:
    from rfc3339_validator import validate_rfc3339
except ImportError as exc:
    raise RuntimeError("rfc3339-validator==0.1.4 is required; install requirements.txt") from exc
from check_containment import parse_time, Malformed


def strict_format_checker():
    checker = FormatChecker()

    @checker.checks("date-time")
    def supported_datetime(value):
        if not isinstance(value, str):
            return True  # type is independently checked by the schema
        if not validate_rfc3339(value.upper()):
            return False
        try:
            parse_time(value)
            return True
        except Malformed:
            return False

    # Detect absent/disabled required checkers as well as a missing dependency.
    for fmt, good, bad in (("date-time", "2026-09-07T00:00:00Z", "not-a-timestamp"),
                           ("date", "2026-09-07", "2026-99-99")):
        if fmt not in checker.checkers or not checker.conforms(good, fmt) or checker.conforms(bad, fmt):
            raise RuntimeError("Required format validation is unavailable: " + fmt)
    return checker
