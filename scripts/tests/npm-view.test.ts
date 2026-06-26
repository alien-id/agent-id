import { describe, expect, test } from 'bun:test';
import { classifyNpmView } from '../lib/npm-view';

describe('classifyNpmView', () => {
  test('exit 0 with matching version → published', () => {
    expect(
      classifyNpmView('2.1.0-beta', {
        status: 0,
        stdout: '2.1.0-beta\n',
        stderr: '',
      }),
    ).toBe('published');
  });

  test('exit 0 with mismatched stdout → not-published', () => {
    expect(
      classifyNpmView('2.1.0', { status: 0, stdout: '1.9.9\n', stderr: '' }),
    ).toBe('not-published');
  });

  test('exit 1 with E404 in stderr → not-published', () => {
    const stderr = `
npm warn Unknown project config "min-release-age".
npm error code E404
npm error 404 No match found for version 99.99.99
npm error 404
    `;
    expect(classifyNpmView('99.99.99', { status: 1, stdout: '', stderr })).toBe(
      'not-published',
    );
  });

  test('exit 1 with "404 Not Found" GET line → not-published', () => {
    const stderr = `
npm error code E404
npm error 404 Not Found - GET https://registry.npmjs.org/@alien-id/never-exists - Not found
    `;
    expect(classifyNpmView('1.0.0', { status: 1, stdout: '', stderr })).toBe(
      'not-published',
    );
  });

  test('exit 1 with ETIMEDOUT → unknown (transient)', () => {
    const stderr = `
npm error code ETIMEDOUT
npm error network request to https://registry.npmjs.org/... timed out
    `;
    expect(classifyNpmView('2.1.0', { status: 1, stdout: '', stderr })).toBe(
      'unknown',
    );
  });

  test('exit 1 with ENOTFOUND → unknown (DNS failure)', () => {
    const stderr = 'npm error code ENOTFOUND\nnpm error errno ENOTFOUND';
    expect(classifyNpmView('2.1.0', { status: 1, stdout: '', stderr })).toBe(
      'unknown',
    );
  });

  test('exit 1 with ECONNRESET → unknown', () => {
    const stderr = 'npm error code ECONNRESET';
    expect(classifyNpmView('2.1.0', { status: 1, stdout: '', stderr })).toBe(
      'unknown',
    );
  });

  test('exit 1 with EAI_AGAIN → unknown (DNS retry)', () => {
    const stderr = 'npm error code EAI_AGAIN';
    expect(classifyNpmView('2.1.0', { status: 1, stdout: '', stderr })).toBe(
      'unknown',
    );
  });

  test('exit null (signalled) → unknown', () => {
    expect(
      classifyNpmView('2.1.0', { status: null, stdout: '', stderr: '' }),
    ).toBe('unknown');
  });

  test('exit 1 with rate-limit / 5xx server text → unknown', () => {
    const stderr = `
npm error code E429
npm error 429 Too Many Requests - GET https://registry.npmjs.org/...
    `;
    expect(classifyNpmView('2.1.0', { status: 1, stdout: '', stderr })).toBe(
      'unknown',
    );
  });

  test('stderr "E404" leak on exit 0 does not flip the published result', () => {
    expect(
      classifyNpmView('1.0.0', {
        status: 0,
        stdout: '1.0.0\n',
        stderr: 'some warning mentioning E404 spuriously',
      }),
    ).toBe('published');
  });
});
