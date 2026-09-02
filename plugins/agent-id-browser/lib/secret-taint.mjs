// The taint every path that injects a secret into a page must leave behind, and
// that every read-back path checks. It lives on its own because both sides need
// it: the session server writes secrets through its tools, and auto-login writes
// them through its own typing — and the session server already imports auto-login,
// so anything auto-login needs cannot live there.

// A field the vault typed a secret into is tagged with this attribute (see
// markSecretField). It rides on the DOM element, not the ref — a re-snapshot
// invalidates refs but only clears "data-aibref", so the taint survives across
// snapshots as long as the site keeps the node. Kept in sync with the literal
// hard-coded inside snapshotInPage (page functions can't close over module scope).
export const SECRET_TAINT_ATTR = "data-aib-secret";

// Tag the element a fill-secret/fill-otp just wrote to, so every later read-back
// (get --what value, get --what attr value, and the snapshot el.value name
// fallback) refuses it — REGARDLESS of the input's `type`. This is what closes
// the leak for non-password fields: OTP/2FA inputs are type=text/tel, and a
// show-password toggle flips a password field to type=text, so a type-only test
// misses them. Best-effort: if the site has already swapped the node out there
// is nothing (and no value) left to tag.
export async function markSecretField(target, selector) {
  await target
    .$eval(selector, (el, attr) => el.setAttribute(attr, "1"), SECRET_TAINT_ATTR)
    .catch(() => {});
}

// The same tag on an element a caller has ALREADY resolved. Preferred over
// `markSecretField` wherever the writer resolved its own target: a site may render
// a hidden duplicate of a field before the visible one (see `firstVisible`), and
// then the selector's first match and the field the value went into are two
// different elements — tagging by selector would leave the filled one readable.
export async function markSecretLocator(locator) {
  await locator
    .evaluate((el, attr) => el.setAttribute(attr, "1"), SECRET_TAINT_ATTR)
    .catch(() => {});
}

// The same tag, for a code spread across a row of boxes. `markSecretField` names
// one element through the ref's selector, and a row holds one character of the
// code in each of its boxes — so tagging the ref alone leaves the rest readable
// through `get --what value`. Every box written to is tainted, including after a
// partial fill, because a partial fill is exactly when those characters are still
// sitting there.
export async function markSecretBoxes(boxes) {
  await Promise.all(boxes.map(markSecretLocator));
}
