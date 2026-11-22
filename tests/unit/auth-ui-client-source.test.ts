/**
 * Client-side contracts of the login and user-management pages. These inspect
 * the component source rather than rendering it, to avoid a jsdom setup.
 */
import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const loginClient = readFileSync(resolve(__dirname, '../../app/(auth)/login/LoginClient.tsx'), 'utf-8');
const usersDir = resolve(__dirname, '../../app/(dashboard)/users');
const createUserDialog = readFileSync(resolve(usersDir, 'CreateUserDialog.tsx'), 'utf-8');
const usersSources = readdirSync(usersDir)
  .filter((file) => file.endsWith('.tsx'))
  .map((file) => [file, readFileSync(resolve(usersDir, file), 'utf-8')] as const);

describe('login page', () => {
  it('replaces /login in the history with a full load of the dashboard or the deep link', () => {
    // A full load gives the dashboard its own document and CSP nonce;
    // replace() keeps Back from returning to /login. The destination is the
    // page the middleware saved in `next` (an MCP consent link, a deep link).
    expect(loginClient).toContain('window.location.replace(next)');
    expect(loginClient).not.toMatch(/window\.location\.assign\(|router\.(push|replace)\(\s*["']\/["']/);
  });
});

describe('users page', () => {
  it('shows the create-user error instead of letting the action throw', () => {
    expect(createUserDialog).toMatch(/runUserAction\(\(\) => createUserAction\(formData\)/);
    expect(createUserDialog).toContain('{createError && (');
  });

  it('checks the password policy before submitting', () => {
    expect(createUserDialog).toContain('passwordPolicyMessage(');
  });

  it('does not use form actions, which reset the fields on failure', () => {
    for (const [file, source] of usersSources) {
      expect(source, file).not.toMatch(/<form[^>]*\baction=\{/);
    }
  });

  it('never awaits a user action without handling its result', () => {
    for (const [file, source] of usersSources) {
      expect(source, file).not.toMatch(/^\s*await (create|update|delete|reset)User\w*Action\(/m);
    }
  });
});
