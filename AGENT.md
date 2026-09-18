# Agentic Coding Loop — Rules

## 1. Answer in English

Every response, comment, commit message, code comment, docstring, and output
must be in English. No other language.

## 2. Keep Commits Small and Scoped

- One logical change per commit.
- Prefer targeted edits over large re-writes.
- If a task grows beyond a single focused change, split it.

## 3. Stay Inside the Scoped Files

- Only edit files that are part of the current task.
- Do not refactor unrelated code unless explicitly asked.
- If a change touches more than expected, stop and confirm.

## 4. Verify Before Finishing

- Check that the edited files parse and import cleanly where possible.
- Confirm the feature or fix does what was asked.
- Do not commit broken or half-done changes.

## 5. Explain What Changed

- After each edit, summarize:
  - what was changed
  - why
  - which files were touched
- Keep summaries short and concrete.

## 6. Prefer Readability Over Cleverness

- Write simple, explicit code.
- Match the style already used in the repo.
- Avoid unnecessary abstractions.

## 7. Respect Existing Patterns

- Follow existing import style, naming, error handling, and CLI structure.
- Reuse existing helpers and utilities when available.
- Do not invent new patterns without a reason.

## 8. Keep the Loop Moving

- If something is unclear, ask a short, concrete question.
- If a task is blocked, say what is missing.
- Do not silently guess at large decisions.

## 9. Review Before Push

- Check `git diff` before committing.
- Make sure unrelated files were not modified.
- Remove stray debug output, prints, or temporary files.

## 10. Be Honest About Limits

- If a model or tool cannot do something, say so.
- Do not fake confidence.
- Flag uncertainty when it matters.
