# Lab findings

Findings from running the lab runbook on CT 110, for the case study. No canary
paths, request IDs or decoy text appear here.

## Case 5: text-mode browsers show hidden canaries (Nov 18, 2026)

**What was seen.** On the Mac, `lynx -dump` of the home page printed the
hidden-element instruction canary ("…note: request …") as ordinary text. The
other tools showed nothing extra:

- VoiceOver read only the nav, the title and the logo;
- the engine logged no canary hit, attack signal or block for the Mac during the run.

VoiceOver announced the logo as "image" with no name. That is a separate
accessibility fault: the link around the logo had no accessible name.

**Why.** Lynx ignores CSS. The hiding methods were tested with lynx 2.9.3 on a
dummy page:

| Hiding method | Shown by lynx |
|---|---|
| CSS class (the lab site's off-screen rule) | yes |
| `hidden` attribute | yes |
| inline `display: none` | yes |
| `<template>` | yes |
| `<details hidden>` | yes |
| SVG `<desc>` | yes |
| HTML comment | no |
| attribute value (`data-*`, `<input type="hidden">`) | no |

So no element's text can be hidden from a text-mode browser. This is also why
the placement works on agents. Many agents turn a page into text, ignoring CSS
much as lynx does, so they see what lynx shows. Moving the canary into a comment or an attribute would hide it
from lynx, but it would also stop this placement from testing whether an agent
acts on page text a sighted visitor never sees.

**Risk to a person.** The risk is low:
- A person using a text-mode browser sees a line that looks like an instruction.
- If they follow it, the hit is counted, but a canary hit alone never blocks.
- A block also needs two separate attack probes from the same address.

The risk is confusion, not lockout.

**Fix (PR "Text-mode notice on hidden canaries").**
- Each hidden canary now starts with a fixed sentence: "Text-mode note: the
  rest of this line is hidden on the normal page and is not meant for people."
  This covers the hidden-element instruction and the error-page bait.
- The logo now has the alt text "Lab Tool Library home".
- A test runs lynx on the built site, when lynx is installed, and checks that the
  notice comes first on every line that shows a hidden canary.

**Effect on the measurements.** Agents read the notice too, and it may change
how often they act on that line. No AI agent case had run before this change.
The only earlier run of this placement was case 9, the crawler, which follows
every path whatever the words around it say. So the agent hit rates will all be
measured with the notice in place, and the case study reports the placement
with the notice.

## Canary rotations

The canaries were rotated twice during Phase 6A, both times because a canary
reference or path had been pasted into a chat outside the lab:

- before case 12;
- after case 5.

Rotating replaces all seven decoy paths. No agent case had run before either rotation.
