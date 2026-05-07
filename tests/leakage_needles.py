"""Shared substrings that safe surfaces (index, logs, repr) must not contain."""

LEAKAGE_NEEDLES: tuple[str, ...] = (
    "SRCLEAKINV8833x",
    "TAGLEAKINV7722y",
    "leaktest.invalid",
    "LEAKCUSTOM",
    "LEAKCOMMENT",
)
