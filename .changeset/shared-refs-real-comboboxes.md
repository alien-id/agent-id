---
"@alien-id/agent-id-browser": minor
---

Enterprise application forms are drivable: one ref space, real comboboxes, and no silently-dropped refs

Three defects that together made an SAP/Taleo-shaped careers form unfillable. All
three were observed on live applications, twice burning an agent's whole tool
budget with no progress.

**Refs meant different things in different tools.** `snapshot` and `form-inspect`
each cleared every `data-aibref` and renumbered from `e1` — but over different
element sets: snapshot over links/buttons/inputs, form-inspect over form controls
only. So `e7` was the First Name input after a form-inspect and a toolbar button
after a snapshot, and nothing detected the difference: a form-fill built from
form-inspect refs silently drove the wrong elements, and the stale-ref error
advised re-running two tools that disagreed. Both modes now number over the UNION
of their selectors in document order, independently of what each reports, so a ref
denotes the same element either way.

**Refs are versioned by the observation that minted them.** They now read `3:e7`,
so a ref held across a re-observation is refused by name instead of resolving
against whatever currently holds that number. Clearing the attributes per scan is
not sufficient alone: the next scan re-tags a possibly different element with the
same `e7`. The check is skipped for unversioned refs and for callers driving
`fillForm` against a hand-built state, so direct API use keeps working.

**Comboboxes were driven with `selectOption`.** That only works on a native
`<select>`; against an `<input role=combobox>` it fails every time with "Element
is not a `<select>` element", and Oracle/Taleo/Workday/SAP render country and
nationality pickers exactly that way. `form-fill` and the bare `select` action now
dispatch on what the element actually is: `selectOption` for a real select, and
for a combobox a click/type/pick that emits real key events via
`pressSequentially`, because autocompletes ignore a value set in one shot and
submit blank. The pick is verified against the control's own value, so a rejected
choice surfaces as a failure instead of a cheerful `ok:true`.

**`type-text`/`fill-text` silently discarded a `--ref`.** They type into whatever
is focused and have no ref parameter, but the CLI dropped the flag before the
session server saw it, so `type-text --ref e27 --text Switzerland` aimed at a
country combobox typed into whatever held focus and reported success — the filter
never saw the text and the widget answered "There were no results". A ref is now
refused by name, pointing at the ref-taking tool (`type`/`fill`) instead.
