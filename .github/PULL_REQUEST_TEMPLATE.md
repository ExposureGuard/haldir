<!--
Thanks for the contribution!

Keep the description tight. Reviewers should be able to understand *what
changed and why* in under 60 seconds. Save deep-dive discussion for the
linked issue.
-->

## Summary

<!-- One or two sentences: what does this PR do? -->

## Why

<!-- Link the issue this closes, or describe the motivation.
     "Closes #123" or "Fixes the AES-128 regression noted in #456" -->

## What changed

- <!-- bullet per meaningful change -->
- <!-- keep it at the change level, not the file level -->

## How I tested

- [ ] Ran `pytest tests/` locally — all pass
- [ ] Self-host still works (`docker compose up -d` + `curl localhost:8000/health` returns 200)
- [ ] Relevant integration example still runs (langchain_agent.py / crewai_crew.py / vercel_ai_sdk.ts)

<!-- Paste any new test output or a repro here if useful. -->

## Checklist

- [ ] Commit messages are tidy (squash exploratory commits)
- [ ] `CHANGELOG.md` entry added (for user-visible changes)
- [ ] Docs updated (README / wiki / module docstrings)
- [ ] No security-sensitive changes **without** a matching note in `SECURITY.md` if needed
