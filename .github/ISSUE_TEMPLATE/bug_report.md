---
name: 🐛 Bug Report
about: An agent did the wrong thing — false positive, missed detection, command failed
title: '[BUG] '
labels: bug
assignees: ''
---

## What happened?

<!-- Describe the bug in 1-2 sentences -->

## Which agent?

<!-- e.g. backdoor-hunter, cryptojacker, ssl-tester, jwt-hunter -->

## What did you expect to happen?

## What actually happened?

## Reproduction steps

```bash
# Paste the exact command(s) you ran
```

## Environment

- **OS:** <!-- e.g. Ubuntu 24.04, Debian 12, Fedora 41 -->
- **ClaudeOS version:** <!-- output of `claudeos version` -->
- **Agent file:** <!-- paste output of `claudeos agents show <agent-name> | head -5` -->

## Log output (if any)

```
<!-- Paste relevant output here -->
```

## Severity

- [ ] 🚨 **Critical** — agent is missing real attacks (security gap)
- [ ] 🟠 **High** — agent crashes / blocks workflow
- [ ] 🟡 **Medium** — false positive / wrong output
- [ ] 🟢 **Low** — cosmetic / typo

## Bonus: did you fix it?

<!-- If you have a fix, paste a diff or open a PR. We merge fast. -->
