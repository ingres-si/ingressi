/**
 * The Access lists editor's draft (app/(dashboard)/access-lists/access-list-draft.ts):
 * dirty tracking, moving rules, value parsing, and the save payload the
 * model receives (rule ids kept, members added, removed and given new
 * passwords).
 */
import { describe, expect, it } from 'vitest';
import {
  draftFromList,
  draftRuleError,
  draftToSave,
  generatePassword,
  isDraftDirty,
  moveRule,
  newDraftMember,
  newDraftRule,
  parseDraftValues,
} from '@/app/(dashboard)/access-lists/access-list-draft';

const list = {
  name: 'Office and VPN',
  description: 'Office range and WireGuard peers',
  rules: [
    { id: 1, action: 'allow' as const, kind: 'ip' as const, values: ['203.0.113.0/26'], note: 'Office', expiresAt: null },
    { id: 2, action: 'allow' as const, kind: 'ip' as const, values: ['10.13.13.0/24'], note: null, expiresAt: null },
  ],
  defaultAction: 'deny' as const,
  denyStatus: 403,
  denyBody: null,
  denyRedirectUrl: null,
  failClosed: false,
  skipAuthForAllowed: false,
  entries: [{ id: 5, username: 'alice', createdAt: '2026-02-04T10:00:00.000Z' }],
};

describe('access list draft', () => {
  it('starts clean and notices every change', () => {
    const saved = draftFromList(list);
    expect(isDraftDirty(draftFromList(list), saved)).toBe(false);
    expect(isDraftDirty({ ...saved, name: 'Office' }, saved)).toBe(true);
    expect(isDraftDirty({ ...saved, rules: moveRule(saved.rules, 0, 1) }, saved)).toBe(true);
    expect(isDraftDirty({ ...saved, failClosed: true }, saved)).toBe(true);
    expect(isDraftDirty({ ...saved, members: saved.members.map((member) => ({ ...member, removed: true })) }, saved)).toBe(true);
    // Retyping the same values is not a change.
    expect(isDraftDirty({ ...saved, rules: saved.rules.map((rule) => ({ ...rule, valuesText: ` ${rule.valuesText}, ` })) }, saved)).toBe(false);
  });

  it('moves rules up and down within bounds', () => {
    const rules = draftFromList(list).rules;
    expect(moveRule(rules, 1, -1).map((rule) => rule.id)).toEqual([2, 1]);
    expect(moveRule(rules, 0, -1)).toBe(rules);
    expect(moveRule(rules, 1, 1)).toBe(rules);
  });

  it('parses typed values and explains the bad ones', () => {
    expect(parseDraftValues('country', 'it fr, IT')).toEqual({ values: ['IT', 'FR'], errors: [] });
    expect(parseDraftValues('ip', '10.0.0.1, 10.0.0.300').errors).toEqual(['"10.0.0.300" is not an IP address or CIDR range']);
    expect(draftRuleError(newDraftRule('deny', 'asn'))).toBe('Add at least one value');
    expect(draftRuleError({ ...newDraftRule('deny', 'asn'), valuesText: 'AS64500' })).toBeNull();
  });

  it('builds the save payload: rule ids kept, members added, removed and given new passwords', () => {
    const draft = draftFromList(list);
    draft.rules = [...draft.rules, { ...newDraftRule('deny', 'country'), valuesText: 'kp, ir', note: ' Sanctions ' }];
    draft.members = [{ ...draft.members[0], newPassword: 'New-Passw0rd!' }, newDraftMember('bob', 'Bob-Passw0rd!')];
    draft.denyStatus = '451';
    draft.denyRedirectUrl = ' ';
    expect(draftToSave(draft, { system: false, expectedUpdatedAt: '2026-10-03T12:00:00.000Z' })).toEqual({
      name: 'Office and VPN',
      description: 'Office range and WireGuard peers',
      defaultAction: 'deny',
      expectedUpdatedAt: '2026-10-03T12:00:00.000Z',
      rules: [
        { id: 1, action: 'allow', kind: 'ip', values: ['203.0.113.0/26'], note: 'Office', expiresAt: null },
        { id: 2, action: 'allow', kind: 'ip', values: ['10.13.13.0/24'], note: null, expiresAt: null },
        { action: 'deny', kind: 'country', values: ['KP', 'IR'], note: 'Sanctions', expiresAt: null },
      ],
      denyStatus: 451,
      denyBody: null,
      denyRedirectUrl: null,
      failClosed: false,
      skipAuthForAllowed: false,
      members: { add: [{ username: 'bob', password: 'Bob-Passw0rd!' }], remove: [], passwords: [{ id: 5, password: 'New-Passw0rd!' }] },
    });
  });

  it('never sends the name or the default action of the Blocked sources list', () => {
    const payload = draftToSave(draftFromList({ ...list, entries: [] }), { system: true });
    expect(payload).not.toHaveProperty('name');
    expect(payload).not.toHaveProperty('defaultAction');
    expect(payload.members).toEqual({ add: [], remove: [], passwords: [] });
  });

  it('generates strong passwords', () => {
    const password = generatePassword();
    expect(password).toHaveLength(20);
    expect(generatePassword()).not.toBe(password);
  });
});
