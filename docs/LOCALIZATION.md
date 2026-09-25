# Localizing Secrets Kit

Secrets Kit uses bundled Python dictionaries for human-facing CLI text. English is the default; French, Spanish and German catalogs are included. No network translation service or optional localization package is required.

## Selecting a language

Set `SECKIT_LANGUAGE` for an invocation or export it in your shell:

```bash
SECKIT_LANGUAGE=fr seckit --help
SECKIT_LANGUAGE=es seckit daemon --help
SECKIT_LANGUAGE=de seckit doctor --help
SECKIT_LANGUAGE=en seckit --help
```

Selection uses the first nonempty variable in this order: `SECKIT_LANGUAGE`, `LC_ALL`, `LC_MESSAGES`, `LANG`. Regional forms such as `fr_CA.UTF-8`, `es-MX` and `de_DE@euro` select the corresponding language. English variants, `C`, `POSIX` and unsupported languages select English. An unsupported explicit override selects English rather than falling through to another variable. Secrets Kit does not call `setlocale` or change process-wide number/date formatting.

For an SSH invocation, set the language in the remote command environment; SSH does not necessarily forward your local environment. The standalone shell installer does not yet consume these Python catalogs.

## Translation boundary

Translate human-facing help, prompts, warnings and feedback, not command names, option names, JSON keys, stable error codes, paths, protocol identifiers, secret values or user-supplied text. An embedded operating-system/provider error may remain in its original language. Do not translate a serialized payload, exception representation or whole output stream.

The existing confirmation behavior accepts only `y` or `yes` (case-insensitive). Every catalog deliberately retains `[y/N]`; any localized yes/no input support must be implemented and tested separately. Empty input remains a refusal.

## Adding or changing messages

1. Add a stable descriptive key and the English template to `src/secrets_kit/locales/en_US.py`.
2. Import `msg` directly from `secrets_kit.locale` at the human-output boundary and use `msg("key", name=value)`. Do not format or concatenate translated fragments when one complete template expresses the message.
3. Add the same key to `fr.py`, `es.py` and `de.py`. Each file contains its own explicit `STRINGS` dictionary.
4. Preserve named placeholders, conversions and format specifications exactly: `{path}`, `{backend!r}` and any formatting suffix must match English. Preserve literal commands and shell examples.
5. Run `make test-locales` and `make test-fast`. Review the rendered help and security-sensitive prompts, not just dictionary syntax.

Missing translations fall back to English at runtime, but catalog parity tests fail so omissions cannot silently pass the release checks. Unknown message keys and invalid/missing formatting arguments remain programming errors.

## Adding another language

Create `locales/<language>.py` with an explicit `STRINGS` dictionary matching the English keys. Add a direct import and entry in `locale.TABLES`, then include its language code in `active_locale()`. There is no dynamic plugin loading. Extend alias and selection tests in `tests/test_locale.py`. Preserve the English fallback and avoid changing machine-readable output.

Obtain a fluent-language review, especially for destructive-operation confirmations, permission failures, encryption warnings and recovery guidance. Automated key/placeholder checks do not establish translation quality.

## Coverage and release qualification

The bundled catalog and previously literal parser help are translated. This is not yet a claim that every product message is localized: standalone installer feedback, standard-library argparse diagnostics, raw backend/service exceptions and remaining command status labels/messages still require extraction or explicit classification before full-language release qualification.

Documentation translation is not required. Before claiming complete language support, run installed-product help, errors, enrollment, daemon lifecycle, local/remote installation and uninstall in each language. Verify JSON, protocol output and explicitly retrieved secret bytes are identical across languages. Keep uncovered paths visible in the release checklist.
