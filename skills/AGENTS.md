# Inspektor Gadget troubleshooting skills

This directory bundles two complementary **agent skills** that teach an AI
assistant to debug systems at the kernel level with **Inspektor Gadget (IG)** —
eBPF-based tracing that ties every kernel event (syscalls, packets, DNS,
capability checks, OOM kills) back to the workload that caused it.

## Which skill to use

| Use this skill | When the target is | Launcher |
|---|---|---|
| **`kubernetes-troubleshooting`** | a **Kubernetes** pod / Service / workload (cluster-wide, k8s-enriched) | `kubectl gadget run <gadget>:latest` |
| **`linux-troubleshooting`** | a **single Linux host / VM / container runtime** (no cluster) | `sudo ig run <gadget>:latest` |

Both expose the **same gadgets, flags, and fields** — they differ only in the
launcher and the enrichment metadata (`k8s.*` vs `runtime.*`). Each skill's
`references/*-companion.md` explains when to hop to the other.

## The shared mental model

1. **Route** the symptom to a domain (networking / security / process-lifecycle /
   storage-fs / performance) and a candidate gadget (each skill's SKILL.md has a
   symptom→gadget shortlist; `references/gadget-catalog.md` has the full grouped
   list).
2. **Discover, don't guess** — read the gadget's real flags and fields at run
   time with `<gadget>:latest --help` (and `-o json | jq keys` on a live sample).
   Never hardcode a field name from memory; gadget images evolve and new gadgets
   ship. This one rule is what keeps the skills correct against **any future
   upstream gadget**.
3. **Run bounded** — always scope (`-n`/`-p`/`-c`/`--host`) and time-box
   (`--timeout`, `--max-entries`) so a trace can't flood context or the cluster.
4. **Read the columns** — inspect the enriched fields to confirm/refute a
   hypothesis, then narrow and repeat until root cause.

## Progressive disclosure

Keep the entry point small and load depth on demand:

- **SKILL.md** — the always-loaded router: what the skill is for, the 4-step
  loop, the symptom→gadget shortlist, and pointers. Deliberately thin.
- **references/** — loaded only when the task needs it: the full gadget catalog,
  per-domain playbooks (with disambiguation reasoning + verified flags), the
  discover-don't-guess mechanics, common flags, setup, and companion routing.

This mirrors the way IG itself treats each gadget as the single source of truth
for its own interface: the skill teaches the agent to *ask the gadget*, so the
docs stay small and never drift.

Read a skill's own `SKILL.md` first; open a `references/*.md` only when you're
working that domain.
