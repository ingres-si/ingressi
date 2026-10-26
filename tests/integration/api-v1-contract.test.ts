/**
 * v1 REST API contract test.
 *
 * Posts payloads using the field names documented in OpenAPI (camelCase) and
 * verifies the model actually persists them. Catches snake/camel mismatches
 * between the OpenAPI spec and the model input contract.
 *
 * Background: prior to 2026-05, OpenAPI documented snake_case for most
 * resource inputs while the model layer expected camelCase. The spread
 * silently dropped fields — `geoblock_mode` was the user-visible symptom but
 * the same shape applied to certificate_id, ssl_forced, hsts_subdomains,
 * skip_https_hostname_validation, load_balancer, dns_resolver, custom_*,
 * location_rules, and the L4 listen_addresses / matchers fields.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { TestDb } from '../helpers/db';

const ctx = vi.hoisted(() => ({ db: null as unknown as TestDb }));

vi.mock('../../src/lib/db', async () => {
  const { createTestDb } = await import('../helpers/db');
  ctx.db = createTestDb();
  return (await import('../helpers/db-module')).mockDbModule(() => ctx.db);
});

vi.mock('../../src/lib/caddy', () => ({
  applyCaddyConfig: vi.fn().mockResolvedValue({ ok: true }),
}));

vi.mock('../../src/lib/audit', () => ({
  logAuditEvent: vi.fn(),
}));

vi.mock('../../src/lib/api-auth', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/lib/api-auth')>();
  return {
    ...actual,
    requireApiPermission: vi.fn((request: unknown) => import('@/tests/helpers/permission-mocks').then((m) => m.viaRequireApiAdmin(request))),
    requireApiAdmin: vi.fn().mockResolvedValue({ userId: 1, role: 'admin', authMethod: 'bearer' }),
    requireApiUser: vi.fn().mockResolvedValue({ userId: 1, role: 'admin', authMethod: 'bearer' }),
  };
});

import { POST as createProxyHost } from '../../app/api/v1/proxy-hosts/route';
import { POST as createL4ProxyHost } from '../../app/api/v1/l4-proxy-hosts/route';
import { POST as createCertificate } from '../../app/api/v1/certificates/route';
import { POST as createCaCertificate } from '../../app/api/v1/ca-certificates/route';
import { GET as getOpenApi } from '../../app/api/v1/openapi.json/route';
import * as schema from '../../src/lib/db/schema';
import { getCertificate, migrateLegacyCertificateStorage } from '../../src/lib/models/certificates';
import { decryptSecret, isEncryptedSecret } from '../../src/lib/secret';

function mockRequest(body: unknown): any {
  return {
    headers: { get: () => null },
    method: 'POST',
    nextUrl: { pathname: '/api/v1/test', searchParams: new URLSearchParams() },
    json: async () => body,
  };
}

beforeEach(async () => {
  for (const table of [
    schema.proxyHosts,
    schema.l4ProxyHosts,
    schema.certificates,
    schema.caCertificates,
    schema.settings,
    schema.users,
  ]) {
    await ctx.db.delete(table).catch(() => {});
  }
  await ctx.db.insert(schema.users).values({
    id: 1,
    email: 'test@example.com',
    name: 'Test User',
    role: 'admin',
    provider: 'credentials',
    subject: 'test',
    status: 'active',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });
});

/**
 * Static guard against drift: top-level properties in every Input/resource
 * schema must be camelCase. Snake_case is allowed inside meta-JSON
 * sub-schemas (geoblock_*, waf inner fields, redirect_url, etc.) and on a
 * handful of legacy endpoints that read snake_case body fields directly.
 */
describe('v1 OpenAPI schemas: no top-level snake_case', () => {
  // Schemas whose properties are stored as snake_case JSON in meta/settings.
  const META_SHAPED_SCHEMAS = new Set([
    'AuthentikConfig', // mixed snake/camel inside, deliberately
    'GeoBlockConfig',
    'WafConfig',
    'WafSettings',
    'MtlsConfig',
    'RewriteConfig',
    'IngressiForwardAuthConfig',
    'TrustedProxiesSettings',
  ]);
  // Properties on otherwise-camelCase schemas that we intentionally keep
  // snake_case because the route handler reads them that way.
  const LEGACY_SNAKE_KEYS = new Set([
    'TokenInput.expires_at',
  ]);

  it('uses camelCase for every top-level resource property', async () => {
    const response = await getOpenApi(mockRequest(undefined));
    const spec = await response.json() as any;
    const schemas = spec.components.schemas as Record<string, any>;
    const offenders: string[] = [];

    for (const [schemaName, schemaDef] of Object.entries(schemas)) {
      if (META_SHAPED_SCHEMAS.has(schemaName)) continue;
      if (typeof schemaDef !== 'object' || !schemaDef?.properties) continue;
      for (const key of Object.keys(schemaDef.properties)) {
        if (key.includes('_') && !LEGACY_SNAKE_KEYS.has(`${schemaName}.${key}`)) {
          offenders.push(`${schemaName}.${key}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });
});

describe('v1 API contract: camelCase round-trip', () => {
  it('POST /api/v1/proxy-hosts persists every documented camelCase field', async () => {
    const payload = {
      name: 'Contract Host',
      domains: ['contract.example.com'],
      upstreams: ['10.0.0.1:8080'],
      certificateId: null,
      accessListId: null,
      sslForced: false,
      hstsEnabled: false,
      hstsSubdomains: true,
      allowWebsocket: false,
      preserveHostHeader: false,
      skipHttpsHostnameValidation: true,
      enabled: true,
      customReverseProxyJson: '{"flush_interval": -1}',
      customPreHandlersJson: null,
      geoblock: {
        enabled: true,
        block_countries: ['CN'],
        block_continents: [],
        block_asns: [],
        block_cidrs: [],
        block_ips: [],
        allow_countries: [],
        allow_continents: [],
        allow_asns: [],
        allow_cidrs: [],
        allow_ips: [],
        trusted_proxies: [],
        fail_closed: false,
        response_status: 403,
        response_body: 'Forbidden',
        response_headers: {},
        redirect_url: '',
      },
      geoblockMode: 'override',
    };

    const response = await createProxyHost(mockRequest(payload));
    expect(response.status).toBe(201);
    const data = await response.json();

    expect(data.name).toBe('Contract Host');
    expect(data.sslForced).toBe(false);
    expect(data.hstsSubdomains).toBe(true);
    expect(data.skipHttpsHostnameValidation).toBe(true);
    expect(data.customReverseProxyJson).toBe('{"flush_interval": -1}');
    expect(data.geoblockMode).toBe('override');
    expect(data.geoblock.block_countries).toEqual(['CN']);
  });

  it('POST /api/v1/proxy-hosts returns a safe 400 for mTLS without trust material', async () => {
    const response = await createProxyHost(mockRequest({
      name: 'No Trust Host',
      domains: ['no-trust.example.com'],
      upstreams: ['10.0.0.1:8080'],
      mtls: { enabled: true },
    }));

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: expect.stringMatching(/no trusted client certificates, roles, or CA/i),
    });
  });

  it('POST /api/v1/proxy-hosts returns a safe 400 for a wildcard without DNS credentials', async () => {
    const response = await createProxyHost(mockRequest({
      name: 'Wildcard Without DNS',
      domains: ['*.example.com'],
      upstreams: ['10.0.0.1:8080'],
    }));

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: expect.stringMatching(/requires a DNS provider/i),
    });
  });

  it('POST /api/v1/l4-proxy-hosts uses listenAddress (string) and matcherValue (array)', async () => {
    const payload = {
      name: 'L4 Contract',
      protocol: 'tcp',
      listenAddress: ':15555',
      upstreams: ['db:5432'],
      matcherType: 'tls_sni',
      matcherValue: ['db.example.com'],
      tlsTermination: false,
      proxyProtocolVersion: null,
      proxyProtocolReceive: true,
      enabled: true,
      geoblock: {
        enabled: true,
        block_countries: [],
        block_continents: [],
        block_asns: [],
        block_cidrs: ['203.0.113.0/24'],
        block_ips: [],
        allow_countries: [],
        allow_continents: [],
        allow_asns: [],
        allow_cidrs: [],
        allow_ips: [],
      },
      geoblockMode: 'override',
    };

    const response = await createL4ProxyHost(mockRequest(payload));
    expect(response.status).toBe(201);
    const data = await response.json();

    expect(data.listenAddress).toBe(':15555');
    expect(data.matcherType).toBe('tls_sni');
    expect(data.matcherValue).toEqual(['db.example.com']);
    expect(data.proxyProtocolReceive).toBe(true);
    expect(data.geoblockMode).toBe('override');
    expect(data.geoblock.block_cidrs).toEqual(['203.0.113.0/24']);
  });

  it('POST /api/v1/certificates persists domainNames and autoRenew', async () => {
    const payload = {
      name: 'Contract Cert',
      type: 'managed',
      domainNames: ['contract-cert.example.com'],
      autoRenew: false,
    };
    const response = await createCertificate(mockRequest(payload));
    expect(response.status).toBe(201);
    const data = await response.json();
    expect(data.domainNames).toEqual(['contract-cert.example.com']);
    expect(data.autoRenew).toBe(false);
  });

  it('POST /api/v1/certificates persists an imported key but never returns it', async () => {
    const privateKeyPem = '-----BEGIN PRIVATE KEY-----\nmultiline\nprivate-key-sentinel\n-----END PRIVATE KEY-----';
    const payload = {
      name: 'Write-only imported key',
      type: 'imported',
      domainNames: ['write-only.example.com'],
      autoRenew: false,
      certificatePem: '-----BEGIN CERTIFICATE-----\npublic-data\n-----END CERTIFICATE-----',
      privateKeyPem,
    };

    const response = await createCertificate(mockRequest(payload));
    const bodyText = await response.text();
    const data = JSON.parse(bodyText);
    const stored = await ctx.db.query.certificates.findFirst({
      where: (table, { eq }) => eq(table.id, data.id),
    });

    expect(response.status).toBe(201);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(data.hasPrivateKey).toBe(true);
    expect(data.privateKeyPem).toBeUndefined();
    expect(bodyText).not.toContain(privateKeyPem);
    expect(bodyText).not.toContain('private-key-sentinel');
    expect(stored?.privateKeyPem).toBeDefined();
    expect(isEncryptedSecret(stored!.privateKeyPem!)).toBe(true);
    expect(decryptSecret(stored!.privateKeyPem!)).toBe(privateKeyPem);
  });

  it('migrates legacy plaintext certificate keys without changing operational reads', async () => {
    const privateKeyPem = '-----BEGIN PRIVATE KEY-----\nlegacy-key-sentinel\n-----END PRIVATE KEY-----';
    const now = new Date().toISOString();
    const [row] = await ctx.db.insert(schema.certificates).values({
      name: 'Legacy imported key',
      type: 'imported',
      domainNames: JSON.stringify(['legacy.example.com']),
      autoRenew: false,
      certificatePem: '-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----',
      privateKeyPem,
      createdAt: now,
      updatedAt: now,
    }).returning();

    await expect(migrateLegacyCertificateStorage()).resolves.toBe(1);
    await expect(migrateLegacyCertificateStorage()).resolves.toBe(0);

    const stored = await ctx.db.query.certificates.findFirst({
      where: (table, { eq }) => eq(table.id, row.id),
    });
    expect(isEncryptedSecret(stored!.privateKeyPem!)).toBe(true);
    expect((await getCertificate(row.id))?.privateKeyPem).toBe(privateKeyPem);
  });

  it('scrubs legacy certificate provider secrets from storage', async () => {
    const providerSecret = 'legacy-provider-option-secret-sentinel';
    const now = new Date().toISOString();
    const [row] = await ctx.db.insert(schema.certificates).values({
      name: 'Legacy managed certificate',
      type: 'managed',
      domainNames: JSON.stringify(['managed.example.com']),
      autoRenew: true,
      providerOptions: JSON.stringify({ provider: 'cloudflare', api_token: providerSecret }),
      createdAt: now,
      updatedAt: now,
    }).returning();

    await expect(migrateLegacyCertificateStorage()).resolves.toBe(1);
    await expect(migrateLegacyCertificateStorage()).resolves.toBe(0);

    const stored = await ctx.db.query.certificates.findFirst({
      where: (table, { eq }) => eq(table.id, row.id),
    });
    expect(stored?.providerOptions).toBe('{"provider":"cloudflare"}');
    expect(stored?.providerOptions).not.toContain(providerSecret);
    expect((await getCertificate(row.id))?.providerOptions).toEqual({ provider: 'cloudflare' });
  });

  it('POST /api/v1/ca-certificates persists certificatePem and hasPrivateKey', async () => {
    const fakePem = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';
    const payload = {
      name: 'Contract CA',
      certificatePem: fakePem,
      privateKeyPem: '-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----',
    };
    const response = await createCaCertificate(mockRequest(payload));
    expect(response.status).toBe(201);
    const data = await response.json();
    expect(data.name).toBe('Contract CA');
    expect(data.certificatePem).toBe(fakePem);
    expect(data.hasPrivateKey).toBe(true);
  });
});

describe('v1 OpenAPI references', () => {
  it('resolves every $ref to a defined component', async () => {
    const response = await getOpenApi(mockRequest(undefined));
    const spec = await response.json() as any;
    const missing = new Set<string>();
    const visit = (node: unknown): void => {
      if (Array.isArray(node)) {
        node.forEach(visit);
      } else if (node && typeof node === 'object') {
        for (const [key, value] of Object.entries(node)) {
          if (key === '$ref' && typeof value === 'string') {
            const [, section, name] = value.match(/^#\/components\/([^/]+)\/(.+)$/) ?? [];
            if (!section || !spec.components?.[section]?.[name]) missing.add(value);
          } else {
            visit(value);
          }
        }
      }
    };
    visit(spec);
    expect([...missing]).toEqual([]);
  });
});
