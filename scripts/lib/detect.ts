import type { Classification } from './npm-view';

// A pending changeset is any `.changeset/*.md` file other than the template
// README. Non-markdown entries (`config.json`, `pre.json`) never count, so an
// active pre-release line is not mistaken for queued work.
export function hasPendingChangesets(entries: string[]): boolean {
  return entries.some((e) => e.endsWith('.md') && e !== 'README.md');
}

// True when any publishable package is absent from the registry. A transient
// `unknown` classification throws rather than degrading to a decision, so a
// network blip can never trip the env-gated publish job nor mask a real release.
export function needsPublish(
  packages: { name: string; version: string }[],
  classify: (name: string, version: string) => Classification,
): boolean {
  let publish = false;
  for (const { name, version } of packages) {
    const classification = classify(name, version);
    if (classification === 'unknown') {
      throw new Error(
        `Cannot determine whether ${name}@${version} is published ` +
          `(transient registry error). Re-run the workflow to retry.`,
      );
    }
    if (classification === 'not-published') publish = true;
  }
  return publish;
}
