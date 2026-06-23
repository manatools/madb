"""
madb/validators.py — Centralised input validation helpers.

Usage in routes:
    from madb.validators import validate_release, validate_arch, validate_bug_number,
                                 validate_page_char, validate_rpm_name, validate_level,
                                 ValidationError

    try:
        release = validate_release(request.args.get("distribution"))
        arch    = validate_arch(request.args.get("architecture"))
    except ValidationError as exc:
        return render_template("notfound.html", data={**base_data, "error": str(exc)}), 400
"""

import re
import madb.config as config

# ---------------------------------------------------------------------------
# Sentinel
# ---------------------------------------------------------------------------


class ValidationError(ValueError):
    """Raised when a query parameter does not meet expectations."""


# ---------------------------------------------------------------------------
# Allowed-value validators
# ---------------------------------------------------------------------------

def validate_release(value: str | None, *, allow_unspecified: bool = True) -> str:
    """Return *value* if it is a known distribution key, else raise ValidationError.

    :param allow_unspecified: when True (default) the sentinel "unspecified" is
        accepted and returned as-is (callers are expected to substitute the
        default release themselves).
    """
    if value is None or value == "":
        return "unspecified" if allow_unspecified else str(config.TOP_RELEASE)

    allowed = set(config.DISTRIBUTION.keys())
    if allow_unspecified:
        allowed.add("unspecified")

    if value not in allowed:
        raise ValidationError(
            f"Unknown distribution '{value}'. "
            f"Allowed values: {sorted(allowed)}"
        )
    return value


def validate_arch(value: str | None, *, allow_indifferent: bool = True) -> str:
    """Return *value* if it is a known architecture key, else raise ValidationError."""
    if value is None or value == "":
        return "indifferent" if allow_indifferent else next(iter(config.ARCHES))

    allowed = set(config.ARCHES.keys())
    if allow_indifferent:
        allowed.add("indifferent")

    if value not in allowed:
        raise ValidationError(
            f"Unknown architecture '{value}'. "
            f"Allowed values: {sorted(allowed)}"
        )
    return value


# ---------------------------------------------------------------------------
# Format validators
# ---------------------------------------------------------------------------

# Reasonable upper-bound for an RPM name / NEVRA fragment.
_RPM_NAME_RE = re.compile(r"^[A-Za-z0-9_.+\-*?]{1,256}$")

def validate_rpm_name(value: str | None, *, allow_empty: bool = False) -> str:
    """Validate that *value* looks like a legal RPM package name/fragment.

    Accepts letters, digits, ``._+-`` up to 256 characters.
    Wildcards (``*``, ``?``) are intentionally excluded here; methods in
    Dnf5MadbBase that need them add them internally.
    """
    if not value:
        if allow_empty:
            return ""
        raise ValidationError("A package name is required.")

    if not _RPM_NAME_RE.match(value):
        raise ValidationError(
            f"Invalid package name '{value}'. "
            "Only alphanumerics and '._+-*?' are allowed (max 256 chars)."
        )
    return value


_BUG_NUMBER_RE = re.compile(r"^\d{1,10}$")

def validate_bug_number(value: str | None) -> str:
    """Validate that *value* is a purely numeric bug identifier."""
    if not value:
        raise ValidationError("A bug number is required.")
    if not _BUG_NUMBER_RE.match(value):
        raise ValidationError(
            f"Invalid bug number '{value}'. Expected a numeric identifier."
        )
    return value


def validate_page_char(value: str | None) -> str:
    """Validate the *page* parameter used in /comparison.

    Accepts a single ASCII letter (A-Z, a-z) or the string ``"0"``
    (which means 'packages starting with a digit').
    """
    if not value:
        return "A"
    if value == "0":
        return "0"
    if len(value) == 1 and value.isalpha() and value.isascii():
        return value.upper()
    raise ValidationError(
        f"Invalid page '{value}'. Expected a single letter (A-Z) or '0'."
    )


def validate_level(value, *, min_level: int = 1, max_level: int = 5) -> int:
    """Validate the dependency graph depth level."""
    try:
        level = int(value)
    except (TypeError, ValueError):
        raise ValidationError(f"Invalid level '{value}'. Expected an integer.")
    if not (min_level <= level <= max_level):
        raise ValidationError(
            f"Level {level} is out of range [{min_level}, {max_level}]."
        )
    return level


def validate_boolean_flag(value: str | None, default: str = "0") -> str:
    """Validate a query parameter used as a boolean flag (``'0'`` / ``'1'``)."""
    if value is None:
        return default
    if value not in ("0", "1"):
        raise ValidationError(
            f"Invalid boolean flag '{value}'. Expected '0' or '1'."
        )
    return value
