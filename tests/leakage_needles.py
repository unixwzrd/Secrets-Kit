"""Shared substrings that safe surfaces (index, logs, repr) must not contain."""

LEAKAGE_NEEDLES: tuple[str, ...] = (
    "SRCLEAKINV8833x",
    "TAGLEAKINV7722y",
    "leaktest.invalid",
    "LEAKCUSTOM",
    "LEAKCOMMENT",
)

# Distinct plaintext used only for stdout/stderr runtime invariant tests.
RUNTIME_INVARIANT_PLAINTEXT = "RTINV_PLAINTEXT_9fbd2a5e"
