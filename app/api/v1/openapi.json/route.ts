import { NextRequest, NextResponse } from "next/server";
import { requireApiPermission, apiErrorResponse } from "@/src/lib/api-auth";
import { APP_VERSION } from "@/src/lib/app-version";
import { BRAND_NAME } from "@/src/lib/brand";
import { PERMISSIONS } from "@/src/lib/permissions";
import { MAX_TAG_LENGTH, MAX_TAGS_PER_HOST } from "@/src/lib/host-tags";
import { MONETIZATION_OPENAPI_PATHS, MONETIZATION_OPENAPI_SCHEMAS, MONETIZATION_OPENAPI_TAG } from "@/ee/monetization/openapi";
import { WHITE_LABEL_OPENAPI_PATHS, WHITE_LABEL_OPENAPI_SCHEMAS, WHITE_LABEL_OPENAPI_TAG } from "@/ee/white-label/openapi";
import { brandName } from "@/ee/white-label/store";
import { GOVERNANCE_OPENAPI_PATHS, GOVERNANCE_OPENAPI_SCHEMAS, GOVERNANCE_OPENAPI_TAGS } from "@/src/lib/governance-openapi";
import {
  APPROVALS_OPENAPI_PATHS,
  APPROVALS_OPENAPI_SCHEMAS,
  APPROVALS_OPENAPI_TAG,
  CHANGE_REQUEST_SUBMITTED_RESPONSE,
  PROTECTED_HOST_NOTE,
  REPLACEMENT_PROTECTED_NOTE,
} from "@/ee/approvals/openapi";
import { COMPLIANCE_OPENAPI_PATHS, COMPLIANCE_OPENAPI_SCHEMAS, COMPLIANCE_OPENAPI_TAG } from "@/ee/compliance/openapi";
import { LDAP_OPENAPI_PATHS, LDAP_OPENAPI_SCHEMAS, LDAP_OPENAPI_TAG } from "@/ee/ldap/openapi";
import { SAML_OPENAPI_PATHS, SAML_OPENAPI_SCHEMAS, SAML_OPENAPI_TAG } from "@/ee/saml/openapi";
import { SCIM_OPENAPI_PATHS, SCIM_OPENAPI_SCHEMAS, SCIM_OPENAPI_TAGS } from "@/ee/scim/openapi";
import {
  ACCESS_REVIEWS_OPENAPI_PATHS,
  ACCESS_REVIEWS_OPENAPI_SCHEMAS,
  ACCESS_REVIEWS_OPENAPI_TAG,
} from "@/ee/access-reviews/openapi";
import { FLEET_OPENAPI_PATHS, FLEET_OPENAPI_SCHEMAS, FLEET_OPENAPI_TAG } from "@/ee/fleet/openapi";
import { SEARCH_OPENAPI_PATHS, SEARCH_OPENAPI_SCHEMAS, SEARCH_OPENAPI_TAG } from "@/src/lib/search-openapi";
import { ANALYTICS_OPENAPI_PATHS, ANALYTICS_OPENAPI_SCHEMAS, ANALYTICS_OPENAPI_TAG } from "@/src/lib/analytics/openapi";
import { QUESTIONS_OPENAPI_PATHS, QUESTIONS_OPENAPI_SCHEMAS } from "@/ee/ai/questions/openapi";
import { WAF_OPENAPI_PATHS, WAF_OPENAPI_SCHEMAS, WAF_OPENAPI_TAG, WAF_TUNING_OPENAPI_PROPERTIES } from "@/src/lib/waf-openapi";
import { ACCESS_LISTS_OPENAPI_PATHS, ACCESS_LISTS_OPENAPI_SCHEMAS, ACCESS_LISTS_OPENAPI_TAG } from "@/src/lib/access-lists-openapi";
import { CERTIFICATE_OVERVIEW_OPENAPI_PATHS, CERTIFICATE_OVERVIEW_OPENAPI_SCHEMAS } from "@/src/lib/certificate-overview-openapi";
import { PROXY_HOST_HEALTH_OPENAPI_PATHS, PROXY_HOST_HEALTH_OPENAPI_SCHEMAS } from "@/src/lib/proxy-host-health-openapi";
import { PROXY_HOST_PREVIEW_OPENAPI_PATHS, PROXY_HOST_PREVIEW_OPENAPI_SCHEMAS } from "@/src/lib/proxy-host-preview-openapi";
import { IDENTITY_OVERVIEW_OPENAPI_PATHS, IDENTITY_OVERVIEW_OPENAPI_SCHEMAS } from "@/src/lib/identity-overview-openapi";
import {
  HIGH_AVAILABILITY_OPENAPI_PATHS,
  HIGH_AVAILABILITY_OPENAPI_SCHEMAS,
  HIGH_AVAILABILITY_OPENAPI_TAG,
} from "@/ee/high-availability/openapi";
import { SHARED_STATE_OPENAPI_PATHS, SHARED_STATE_OPENAPI_SCHEMAS } from "@/ee/high-availability/shared-state/openapi";
import {
  IDENTITY_OPENAPI_PATHS,
  IDENTITY_OPENAPI_SCHEMAS,
  PASSKEYS_OPENAPI_TAG,
  PREFERENCES_OPENAPI_TAG,
} from "@/src/lib/identity-openapi";

const SCOPED_HOSTS_NOTE =
  "With a custom role limited to tagged hosts (its scopeTags), lists only include hosts carrying one of the role's tags, " +
  "a host outside the scope answers 404 exactly like a missing one, and a write may only add or remove the role's own tags " +
  "and must leave at least one of them on the host (so creating a host requires one). Domains or listening ports a host " +
  "outside the scope already uses are refused with 403.";

const spec = {
  openapi: "3.1.0",
  info: {
    title: `${BRAND_NAME} API`,
    version: APP_VERSION,
    description:
      "The REST API of Ingressi, a self-hosted reverse proxy built on Caddy: proxy hosts, certificates, access lists, users and every other dashboard setting. " +
      "Each administrative endpoint needs one permission from the catalogue " +
      "(GET /api/v1/permissions; the endpoint-to-permission table is in ee/docs/custom-roles.md). The built-in admin role " +
      "holds every permission; the built-in user and viewer roles hold none of them; a custom role holds the permissions it " +
      "lists, and for proxy hosts, L4 proxy hosts and certificates can be limited to hosts carrying one of its tags. " +
      "An API token acts with its owner's current role, custom role included. A missing permission answers 403.",
  },
  servers: [{ url: "/" }],
  security: [{ bearerAuth: [] }, { sessionAuth: [] }],
  tags: [
    { name: "Tokens", description: "API token management" },
    { name: "Proxy Hosts", description: "HTTP/HTTPS reverse proxy hosts" },
    { name: "L4 Proxy Hosts", description: "Layer 4 (TCP/UDP) proxy hosts" },
    { name: "Certificates", description: "TLS certificate management" },
    { name: "CA Certificates", description: "Certificate Authority certificates" },
    { name: "Client Certificates", description: "Client certificate management" },
    ACCESS_LISTS_OPENAPI_TAG,
    { name: "Settings", description: "Application settings" },
    WAF_OPENAPI_TAG,
    SEARCH_OPENAPI_TAG,
    { name: "Instances", description: "Multi-instance management" },
    FLEET_OPENAPI_TAG,
    HIGH_AVAILABILITY_OPENAPI_TAG,
    { name: "Users", description: "User management" },
    {
      name: "Roles",
      description:
        "Custom roles: named sets of permissions, optionally limited to hosts with given tags.",
    },
    { name: "Groups", description: "User groups for forward auth access control" },
    { name: "mTLS Roles", description: "Role-based access control for mTLS client certificates" },
    { name: "Forward Auth", description: "Forward auth sessions and per-host access control" },
    ANALYTICS_OPENAPI_TAG,
    { name: "Audit Log", description: "Audit log" },
    { name: "Audit Streaming", description: "Audit log export, hash chain verification, retention and streaming to a SIEM" },
    { name: "SSO", description: "Single sign-on policy for dashboard sign-in" },
    {
      name: "MFA",
      description:
        "Multi-factor authentication for dashboard sign-in (authenticator app with one-time backup codes, or a passkey). " +
        "Setting it up, turning it off and new backup codes use Better Auth's /api/auth/two-factor/* endpoints, " +
        "which need an interactive session and the account password; API tokens cannot change a second factor.",
    },
    { name: "Configuration History", description: "Snapshots of the configuration with diffs and rollback" },
    { name: "Configuration", description: "Export and import the whole configuration as a passphrase-protected file" },
    { name: "Backups", description: "Scheduled, passphrase-encrypted configuration backups to S3-compatible storage" },
    { name: "Alerting", description: "Alert channels, rules, history, mutes and dismissals" },
    { name: "AI", description: "AI analyst: the AI provider, the daily security digest, WAF tuning suggestions and the settings of plain-language analytics questions" },
    MONETIZATION_OPENAPI_TAG,
    WHITE_LABEL_OPENAPI_TAG,
    APPROVALS_OPENAPI_TAG,
    COMPLIANCE_OPENAPI_TAG,
    LDAP_OPENAPI_TAG,
    SAML_OPENAPI_TAG,
    ...SCIM_OPENAPI_TAGS,
    ACCESS_REVIEWS_OPENAPI_TAG,
    ...GOVERNANCE_OPENAPI_TAGS,
    { name: "Caddy", description: "Caddy server operations" },
    { name: "Sessions", description: "Your active management-UI sessions" },
    PASSKEYS_OPENAPI_TAG,
    PREFERENCES_OPENAPI_TAG,
    { name: "OAuth Providers", description: "External OIDC/OAuth2 identity providers for SSO" },
  ],
  paths: {
    // ── API monetization (ee) ───────────────────────────────────────
    ...MONETIZATION_OPENAPI_PATHS,
    // ── White-label (ee) ────────────────────────────────────────────
    ...WHITE_LABEL_OPENAPI_PATHS,
    // ── Change approvals (ee) ───────────────────────────────────────
    ...APPROVALS_OPENAPI_PATHS,
    // ── Compliance reports (ee) ─────────────────────────────────────
    ...COMPLIANCE_OPENAPI_PATHS,
    // ── LDAP directories (ee) ───────────────────────────────────────
    ...LDAP_OPENAPI_PATHS,
    // ── SAML providers (ee) ─────────────────────────────────────────
    ...SAML_OPENAPI_PATHS,
    // ── SCIM provisioning and access reviews (ee) ───────────────────
    ...SCIM_OPENAPI_PATHS,
    ...ACCESS_REVIEWS_OPENAPI_PATHS,
    // ── Fleet management (ee) ───────────────────────────────────────
    ...FLEET_OPENAPI_PATHS,
    // ── WAF: exclusions, per-host modes, events ────────────────────
    ...WAF_OPENAPI_PATHS,
    // ── Search ──────────────────────────────────────────────────────
    ...SEARCH_OPENAPI_PATHS,
    // ── Analytics ───────────────────────────────────────────────────
    ...ANALYTICS_OPENAPI_PATHS,
    // ── Plain-language analytics questions (ee) ─────────────────────
    ...QUESTIONS_OPENAPI_PATHS,
    ...CERTIFICATE_OVERVIEW_OPENAPI_PATHS,
    ...PROXY_HOST_HEALTH_OPENAPI_PATHS,
    ...PROXY_HOST_PREVIEW_OPENAPI_PATHS,
    // ── High availability: certificate storage (ee) ─────────────────
    ...HIGH_AVAILABILITY_OPENAPI_PATHS,
    ...SHARED_STATE_OPENAPI_PATHS,
    // ── Identity ────────────────────────────────────────────────────
    ...IDENTITY_OPENAPI_PATHS,
    ...IDENTITY_OVERVIEW_OPENAPI_PATHS,
    // ── Governance and operations: audit details, versions, setup, overview ──
    ...GOVERNANCE_OPENAPI_PATHS,
    // ── Tokens ──────────────────────────────────────────────────────
    "/api/v1/tokens": {
      get: {
        tags: ["Tokens"],
        summary: "List tokens",
        operationId: "listTokens",
        responses: {
          "200": {
            description: "List of tokens",
            content: {
              "application/json": {
                schema: {
                  type: "array",
                  items: { $ref: "#/components/schemas/Token" },
                },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
      post: {
        tags: ["Tokens"],
        summary: "Create a token",
        description:
          "Requires an interactive cookie-authenticated management session. Bearer tokens cannot create replacement credentials.",
        security: [{ sessionAuth: [] }],
        operationId: "createToken",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/TokenInput" },
            },
          },
        },
        responses: {
          "201": {
            description: "Token created",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    token: { $ref: "#/components/schemas/Token" },
                    raw_token: {
                      type: "string",
                      description:
                        "Plain-text token value. Only returned at creation time.",
                    },
                  },
                  required: ["token", "raw_token"],
                },
              },
            },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },
    "/api/v1/tokens/{id}": {
      delete: {
        tags: ["Tokens"],
        summary: "Delete a token",
        operationId: "deleteToken",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { $ref: "#/components/responses/Ok" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },

    // ── Sessions ────────────────────────────────────────────────────
    "/api/v1/sessions": {
      get: {
        tags: ["Sessions"],
        summary: "List your active sessions",
        description:
          "Your active dashboard sessions, the current one first, with the device read from the User-Agent and the approximate " +
          "place (GeoLite2 country and network) of the address it signed in from. Neither is stored. A token with scopes gets 403.",
        operationId: "listSessions",
        responses: {
          "200": {
            description: "Active sessions for the authenticated user",
            content: {
              "application/json": {
                schema: { type: "array", items: { $ref: "#/components/schemas/Session" } },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
      delete: {
        tags: ["Sessions"],
        summary: "Revoke all of your other sessions",
        description: "Signs out every session except the one making the request. Recorded as sessions_revoked.",
        operationId: "revokeOtherSessions",
        responses: {
          "200": {
            description: "Count of revoked sessions",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: { revoked: { type: "integer" } },
                  required: ["revoked"],
                },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
    },
    "/api/v1/sessions/{id}": {
      delete: {
        tags: ["Sessions"],
        summary: "Revoke one of your sessions",
        operationId: "revokeSession",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { $ref: "#/components/responses/Ok" },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },

    // ── Proxy Hosts ─────────────────────────────────────────────────
    "/api/v1/proxy-hosts": {
      get: {
        tags: ["Proxy Hosts"],
        summary: "List proxy hosts",
        description: `Permission proxy_hosts:read. ${SCOPED_HOSTS_NOTE}`,
        operationId: "listProxyHosts",
        responses: {
          "200": {
            description: "List of proxy hosts",
            content: {
              "application/json": {
                schema: {
                  type: "array",
                  items: { $ref: "#/components/schemas/ProxyHost" },
                },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
      post: {
        tags: ["Proxy Hosts"],
        summary: "Create a proxy host",
        description:
          `Permission proxy_hosts:write. ${SCOPED_HOSTS_NOTE} A non-administrator cannot set custom Caddy JSON, proxy to ` +
          "port 2019 (Caddy's admin API) or reference a certificate, access list, client certificate or mTLS role their role cannot read." + PROTECTED_HOST_NOTE,
        operationId: "createProxyHost",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/ProxyHostInput" },
            },
          },
        },
        responses: {
          "201": {
            description: "Proxy host created",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ProxyHost" },
              },
            },
          },
          "202": { $ref: "#/components/responses/ChangeRequestSubmitted" },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },
    "/api/v1/proxy-hosts/{id}": {
      get: {
        tags: ["Proxy Hosts"],
        summary: "Get a proxy host",
        description: "Permission proxy_hosts:read. A host outside the caller's tag scope answers 404.",
        operationId: "getProxyHost",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": {
            description: "Proxy host",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ProxyHost" },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      put: {
        tags: ["Proxy Hosts"],
        summary: "Update a proxy host",
        description: `Permission proxy_hosts:write. ${SCOPED_HOSTS_NOTE}` + PROTECTED_HOST_NOTE,
        operationId: "updateProxyHost",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/ProxyHostInput" },
            },
          },
        },
        responses: {
          "200": {
            description: "Proxy host updated",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ProxyHost" },
              },
            },
          },
          "202": { $ref: "#/components/responses/ChangeRequestSubmitted" },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      delete: {
        tags: ["Proxy Hosts"],
        summary: "Delete a proxy host",
        description: "Permission proxy_hosts:write. A host outside the caller's tag scope answers 404." + PROTECTED_HOST_NOTE,
        operationId: "deleteProxyHost",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { $ref: "#/components/responses/Ok" },
          "202": { $ref: "#/components/responses/ChangeRequestSubmitted" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },

    // ── L4 Proxy Hosts ──────────────────────────────────────────────
    "/api/v1/l4-proxy-hosts": {
      get: {
        tags: ["L4 Proxy Hosts"],
        summary: "List L4 proxy hosts",
        description: `Permission l4_proxy_hosts:read. ${SCOPED_HOSTS_NOTE}`,
        operationId: "listL4ProxyHosts",
        responses: {
          "200": {
            description: "List of L4 proxy hosts",
            content: {
              "application/json": {
                schema: {
                  type: "array",
                  items: { $ref: "#/components/schemas/L4ProxyHost" },
                },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
      post: {
        tags: ["L4 Proxy Hosts"],
        summary: "Create an L4 proxy host",
        description:
          `Permission l4_proxy_hosts:write. ${SCOPED_HOSTS_NOTE} A non-administrator cannot proxy to port 2019 (Caddy's admin API).` + PROTECTED_HOST_NOTE,
        operationId: "createL4ProxyHost",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/L4ProxyHostInput" },
            },
          },
        },
        responses: {
          "201": {
            description: "L4 proxy host created",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/L4ProxyHost" },
              },
            },
          },
          "202": { $ref: "#/components/responses/ChangeRequestSubmitted" },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },
    "/api/v1/l4-proxy-hosts/{id}": {
      get: {
        tags: ["L4 Proxy Hosts"],
        summary: "Get an L4 proxy host",
        description: "Permission l4_proxy_hosts:read. A host outside the caller's tag scope answers 404.",
        operationId: "getL4ProxyHost",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": {
            description: "L4 proxy host",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/L4ProxyHost" },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      put: {
        tags: ["L4 Proxy Hosts"],
        summary: "Update an L4 proxy host",
        description: `Permission l4_proxy_hosts:write. ${SCOPED_HOSTS_NOTE}` + PROTECTED_HOST_NOTE,
        operationId: "updateL4ProxyHost",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/L4ProxyHostInput" },
            },
          },
        },
        responses: {
          "200": {
            description: "L4 proxy host updated",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/L4ProxyHost" },
              },
            },
          },
          "202": { $ref: "#/components/responses/ChangeRequestSubmitted" },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      delete: {
        tags: ["L4 Proxy Hosts"],
        summary: "Delete an L4 proxy host",
        description: "Permission l4_proxy_hosts:write. A host outside the caller's tag scope answers 404." + PROTECTED_HOST_NOTE,
        operationId: "deleteL4ProxyHost",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { $ref: "#/components/responses/Ok" },
          "202": { $ref: "#/components/responses/ChangeRequestSubmitted" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },

    // ── Certificates ────────────────────────────────────────────────
    "/api/v1/certificates": {
      get: {
        tags: ["Certificates"],
        summary: "List certificates",
        operationId: "listCertificates",
        responses: {
          "200": {
            description: "List of certificates",
            content: {
              "application/json": {
                schema: {
                  type: "array",
                  items: { $ref: "#/components/schemas/Certificate" },
                },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
      post: {
        tags: ["Certificates"],
        summary: "Create a certificate",
        operationId: "createCertificate",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/CertificateInput" },
            },
          },
        },
        responses: {
          "201": {
            description: "Certificate created",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Certificate" },
              },
            },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
    },
    "/api/v1/certificates/{id}": {
      get: {
        tags: ["Certificates"],
        summary: "Get a certificate",
        operationId: "getCertificate",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": {
            description: "Certificate",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Certificate" },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      put: {
        tags: ["Certificates"],
        summary: "Update a certificate",
        operationId: "updateCertificate",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/CertificateInput" },
            },
          },
        },
        responses: {
          "200": {
            description: "Certificate updated",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Certificate" },
              },
            },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      delete: {
        tags: ["Certificates"],
        summary: "Delete a certificate",
        description:
          "Proxy hosts that use the certificate switch to automatic TLS (Caddy obtains a certificate for their names). " +
          "400 when one of them has a wildcard name and no default DNS provider is set, since the wildcard could not be obtained automatically.",
        operationId: "deleteCertificate",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { $ref: "#/components/responses/Ok" },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },

    // ── CA Certificates ─────────────────────────────────────────────
    "/api/v1/ca-certificates": {
      get: {
        tags: ["CA Certificates"],
        summary: "List CA certificates",
        operationId: "listCaCertificates",
        responses: {
          "200": {
            description: "List of CA certificates",
            content: {
              "application/json": {
                schema: {
                  type: "array",
                  items: { $ref: "#/components/schemas/CaCertificate" },
                },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
      post: {
        tags: ["CA Certificates"],
        summary: "Create a CA certificate",
        operationId: "createCaCertificate",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/CaCertificateInput" },
            },
          },
        },
        responses: {
          "201": {
            description: "CA certificate created",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/CaCertificate" },
              },
            },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
    },
    "/api/v1/ca-certificates/{id}": {
      get: {
        tags: ["CA Certificates"],
        summary: "Get a CA certificate",
        operationId: "getCaCertificate",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": {
            description: "CA certificate",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/CaCertificate" },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      put: {
        tags: ["CA Certificates"],
        summary: "Update a CA certificate",
        operationId: "updateCaCertificate",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/CaCertificateInput" },
            },
          },
        },
        responses: {
          "200": {
            description: "CA certificate updated",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/CaCertificate" },
              },
            },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      delete: {
        tags: ["CA Certificates"],
        summary: "Delete a CA certificate",
        operationId: "deleteCaCertificate",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { $ref: "#/components/responses/Ok" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },

    // ── Client Certificates ─────────────────────────────────────────
    "/api/v1/client-certificates": {
      get: {
        tags: ["Client Certificates"],
        summary: "List client certificates",
        operationId: "listClientCertificates",
        responses: {
          "200": {
            description: "List of client certificates",
            content: {
              "application/json": {
                schema: {
                  type: "array",
                  items: { $ref: "#/components/schemas/ClientCertificate" },
                },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
      post: {
        tags: ["Client Certificates"],
        summary: "Create a client certificate",
        operationId: "createClientCertificate",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/ClientCertificateInput" },
            },
          },
        },
        responses: {
          "201": {
            description: "Client certificate created",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ClientCertificate" },
              },
            },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
    },
    "/api/v1/client-certificates/{id}": {
      get: {
        tags: ["Client Certificates"],
        summary: "Get a client certificate",
        operationId: "getClientCertificate",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": {
            description: "Client certificate",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ClientCertificate" },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      delete: {
        tags: ["Client Certificates"],
        summary: "Revoke a client certificate",
        operationId: "revokeClientCertificate",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { $ref: "#/components/responses/Ok" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },

    // ── Access Lists ────────────────────────────────────────────────
    ...ACCESS_LISTS_OPENAPI_PATHS,

    // ── Settings ────────────────────────────────────────────────────
    "/api/v1/settings/{group}": {
      get: {
        tags: ["Settings"],
        summary: "Get settings for a group",
        operationId: "getSettings",
        parameters: [
          {
            name: "group",
            in: "path",
            required: true,
            schema: {
              type: "string",
              enum: [
                "general",
                "acme",
                "cloudflare",
                "dns-provider",
                "authentik",
                "metrics",
                "logging",
                "dns",
                "upstream-dns",
                "geoblock",
                "waf",
                "error-pages",
                "default-response",
                "response-headers",
                "trusted-proxies",
                "rate-limit",
                "instance-mode",
                "sync-token",
              ],
            },
            description: "Settings group name",
          },
        ],
        responses: {
          "200": {
            description: "Settings object (shape varies by group). For instance-mode: `{mode}`. For sync-token: `{has_token}`.",
            content: {
              "application/json": {
                schema: {
                  oneOf: [
                    { $ref: "#/components/schemas/GeneralSettings" },
                    { $ref: "#/components/schemas/CloudflareStatus" },
                    { $ref: "#/components/schemas/DnsProviderStatus" },
                    { $ref: "#/components/schemas/AuthentikSettings" },
                    { $ref: "#/components/schemas/MetricsSettings" },
                    { $ref: "#/components/schemas/LoggingSettings" },
                    { $ref: "#/components/schemas/DnsSettings" },
                    { $ref: "#/components/schemas/UpstreamDnsSettings" },
                    { $ref: "#/components/schemas/GeoBlockConfig" },
                    { $ref: "#/components/schemas/WafSettings" },
                    { $ref: "#/components/schemas/DefaultResponseSettings" },
                    { $ref: "#/components/schemas/ResponseHeadersSettings" },
                    { $ref: "#/components/schemas/TrustedProxiesSettings" },
                    { $ref: "#/components/schemas/RateLimitSettings" },
                  ],
                },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
      put: {
        tags: ["Settings"],
        summary: "Update settings for a group",
        operationId: "updateSettings",
        parameters: [
          {
            name: "group",
            in: "path",
            required: true,
            schema: {
              type: "string",
              enum: [
                "general",
                "acme",
                "cloudflare",
                "dns-provider",
                "authentik",
                "metrics",
                "logging",
                "dns",
                "upstream-dns",
                "geoblock",
                "waf",
                "error-pages",
                "default-response",
                "response-headers",
                "trusted-proxies",
                "rate-limit",
                "instance-mode",
                "sync-token",
              ],
            },
            description: "Settings group name",
          },
        ],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                oneOf: [
                  { $ref: "#/components/schemas/GeneralSettings" },
                  { $ref: "#/components/schemas/CloudflareSettings" },
                  { $ref: "#/components/schemas/AuthentikSettings" },
                  { $ref: "#/components/schemas/MetricsSettings" },
                  { $ref: "#/components/schemas/LoggingSettings" },
                  { $ref: "#/components/schemas/DnsSettings" },
                  { $ref: "#/components/schemas/DnsProviderSettings" },
                  { $ref: "#/components/schemas/UpstreamDnsSettings" },
                  { $ref: "#/components/schemas/GeoBlockConfig" },
                  { $ref: "#/components/schemas/WafSettings" },
                  { $ref: "#/components/schemas/DefaultResponseSettings" },
                  { $ref: "#/components/schemas/ResponseHeadersSettings" },
                  { $ref: "#/components/schemas/TrustedProxiesSettings" },
                  { $ref: "#/components/schemas/RateLimitSettings" },
                ],
              },
            },
          },
        },
        responses: {
          "200": {
            description: "Settings updated",
            content: {
              "application/json": { schema: { $ref: "#/components/responses/Ok" } },
            },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
    },

    // ── Instances ───────────────────────────────────────────────────
    "/api/v1/instances": {
      get: {
        tags: ["Instances"],
        summary: "List instances",
        operationId: "listInstances",
        responses: {
          "200": {
            description: "List of instances",
            content: {
              "application/json": {
                schema: {
                  type: "array",
                  items: { $ref: "#/components/schemas/Instance" },
                },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
      post: {
        tags: ["Instances"],
        summary: "Create an instance",
        operationId: "createInstance",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/InstanceInput" },
            },
          },
        },
        responses: {
          "201": {
            description: "Instance created",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Instance" },
              },
            },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
    },
    "/api/v1/instances/{id}": {
      put: {
        tags: ["Instances"],
        summary: "Update an instance",
        description:
          "Changes the name, base URL, sync token or enabled flag; fields left out are kept. A new token keeps the sync key pin. " +
          "A base URL that reaches another sync endpoint removes the pin of the old one, unless another instance or an INSTANCE_SLAVES entry uses it.",
        operationId: "updateInstance",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/InstanceUpdate" },
            },
          },
        },
        responses: {
          "200": {
            description: "Instance updated",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Instance" },
              },
            },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      delete: {
        tags: ["Instances"],
        summary: "Delete an instance",
        description:
          "Also removes the sync key pin of the instance's base URL, unless another instance or an INSTANCE_SLAVES entry uses the same URL. " +
          "To change an instance's name or token, update it instead: that keeps its sync key pin. An instance added again, or moved to a new base URL, is pinned on first use.",
        operationId: "deleteInstance",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { $ref: "#/components/responses/Ok" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },
    "/api/v1/instances/{id}/sync-key-pin": {
      put: {
        tags: ["Instances"],
        summary: "Pin an instance's sync key",
        description:
          "Pins the given sync public key for the instance's base URL, replacing any pin (source \"manual\"), so syncs are sealed to that key only. " +
          "Read the key from the slave itself (its Instance sync page, or GET /api/v1/instances/sync-key there) over a channel you trust. " +
          "Unlike a reset, this leaves no sync that trusts whatever key answers. Instances and INSTANCE_SLAVES entries with the same URL share the pin.",
        operationId: "pinInstanceSyncKey",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/SyncKeyPinInput" },
            },
          },
        },
        responses: {
          "200": {
            description: "The new pin",
            content: { "application/json": { schema: { $ref: "#/components/schemas/SyncKeyPin" } } },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      delete: {
        tags: ["Instances"],
        summary: "Reset an instance's sync key pin",
        description:
          "Removes the sync key pinned for the instance's base URL, so the next sync pins whatever key the slave presents, without a rotation proof. " +
          "Until a key is pinned again, a slave that answers the key request with HTTP 405 (v1.12.0 or earlier) receives the legacy payload, with certificate private keys unsealed. " +
          "Only reset after verifying that the slave was re-keyed on purpose (compare with GET /api/v1/instances/sync-key on the slave); pinning the slave's new key with PUT avoids both risks. " +
          "Instances and INSTANCE_SLAVES entries with the same URL share the pin.",
        operationId: "resetInstanceSyncKeyPin",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { $ref: "#/components/responses/Ok" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { description: "Instance not found, or no sync key is pinned for it", content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } } },
        },
      },
    },
    "/api/v1/instances/sync-key-pins": {
      get: {
        tags: ["Instances"],
        summary: "List sync key pins",
        description:
          "The slave sync keys this master has pinned, by normalized slave base URL, with the instances and INSTANCE_SLAVES entries that sync to each URL. " +
          "INSTANCE_SLAVES entries with a syncKeyId are checked against it instead of the stored pin.",
        operationId: "listSyncKeyPins",
        responses: {
          "200": {
            description: "Sync key pins",
            content: {
              "application/json": {
                schema: {
                  type: "array",
                  items: { $ref: "#/components/schemas/SyncKeyPinListing" },
                },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
      put: {
        tags: ["Instances"],
        summary: "Pin the sync key of a slave URL",
        description:
          "Like PUT /api/v1/instances/{id}/sync-key-pin, by slave base URL: for INSTANCE_SLAVES entries, and for slaves not added yet.",
        operationId: "pinSyncKey",
        parameters: [{ $ref: "#/components/parameters/SyncKeyPinUrl" }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/SyncKeyPinInput" },
            },
          },
        },
        responses: {
          "200": {
            description: "The new pin",
            content: { "application/json": { schema: { $ref: "#/components/schemas/SyncKeyPin" } } },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
      delete: {
        tags: ["Instances"],
        summary: "Reset the sync key pin of a slave URL",
        description:
          "Like DELETE /api/v1/instances/{id}/sync-key-pin, by slave base URL: for INSTANCE_SLAVES entries, and pins no slave uses any more.",
        operationId: "resetSyncKeyPin",
        parameters: [{ $ref: "#/components/parameters/SyncKeyPinUrl" }],
        responses: {
          "200": { $ref: "#/components/responses/Ok" },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { description: "No sync key is pinned for the URL", content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } } },
        },
      },
    },
    "/api/v1/instances/sync-key": {
      get: {
        tags: ["Instances"],
        summary: "Get this instance's sync key",
        description:
          "The sync public key this instance presents as a slave (derived from its SESSION_SECRET). Compare it with the key a master pinned for this slave, " +
          "or pin it on the master (PUT /api/v1/instances/{id}/sync-key-pin there). Compare the full publicKey where it matters: the keyId is a 64-bit fingerprint.",
        operationId: "getInstanceSyncKey",
        responses: {
          "200": {
            description: "Sync public key",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/InstanceSyncKey" },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },
    "/api/v1/instances/sync": {
      post: {
        tags: ["Instances"],
        summary: "Trigger instance sync",
        description:
          "Pushes the master's configuration to every enabled slave. Instances in a promotion-only fleet environment are left " +
          "out (and not counted): they receive configuration through promotions and re-syncs only (tag Fleet). Pull replicas are " +
          "left out too: they fetch it with their next poll.",
        operationId: "syncInstances",
        responses: {
          "200": {
            description: "Sync result",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    total: { type: "integer" },
                    success: { type: "integer" },
                    failed: { type: "integer" },
                    skippedHttp: { type: "integer" },
                  },
                  required: ["total", "success", "failed", "skippedHttp"],
                },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
    },

    // ── Users ───────────────────────────────────────────────────────
    "/api/v1/users": {
      get: {
        tags: ["Users"],
        summary: "List users",
        description: "Permission users:read.",
        operationId: "listUsers",
        responses: {
          "200": {
            description: "List of users",
            content: {
              "application/json": {
                schema: {
                  type: "array",
                  items: { $ref: "#/components/schemas/User" },
                },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
      post: {
        tags: ["Users"],
        summary: "Create a user",
        description:
          "Permission users:write. A caller can only give the new user a role they could assign (see PUT /api/v1/users/{id}): " +
          "only administrators grant admin or an administrator-level custom role, and nobody grants permissions or a host " +
          "scope they do not hold themselves (403).",
        operationId: "createUser",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  email: {
                    type: "string",
                    description:
                      "Stored lowercased. Fails with 400 when another account has it (in any case) or signs in with it as " +
                      "username (for a @localhost address, also with the part before it), or when lowercasing turns a " +
                      "character into an ASCII letter (such as the Kelvin sign)",
                  },
                  password: { type: "string", description: "12-256 characters with upper- and lowercase letters, a digit and a special character" },
                  name: { type: ["string", "null"] },
                  role: {
                    type: "string",
                    enum: ["admin", "user", "viewer"],
                    default: "user",
                    description: "A built-in role; any other value is taken as user. Omit it (or send viewer) with customRoleId.",
                  },
                  customRoleId: {
                    type: ["integer", "null"],
                    description: "A custom role to assign (GET /api/v1/roles); the user is stored with role viewer.",
                  },
                  username: {
                    type: "string",
                    description:
                      "Optional; without it the user gets their email address as username only when it qualifies (see User.username). " +
                      "Username for the login page, which signs in by username only, ignoring case. Surrounding whitespace is removed; " +
                      "the rest must be 3-255 characters of lowercase letters (a-z), digits and _ . @ -, and must not be another " +
                      "account's username, email address or forward-auth portal name (the email <name>@localhost), compared " +
                      "case-insensitively. Otherwise the request fails with 400 and no user is created.",
                  },
                },
                required: ["email", "password"],
              },
            },
          },
        },
        responses: {
          "201": {
            description: "User created",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/User" },
              },
            },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": {
            description:
              "Missing users:write, or a role the caller may not grant",
            content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } },
          },
        },
      },
    },
    "/api/v1/users/{id}": {
      get: {
        tags: ["Users"],
        summary: "Get a user",
        description: "Allowed with users:read, and for every caller on their own account.",
        operationId: "getUser",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": {
            description: "User",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/User" },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      put: {
        tags: ["Users"],
        summary: "Update a user",
        description:
          "Permission users:write. Role changes: nobody changes their own role or status (400); a non-administrator can only " +
          "edit users whose access they hold themselves (so never an administrator), only administrators grant admin or an " +
          "administrator-level custom role, and nobody grants permissions or a host scope they do not hold (403). Demoting, " +
          "disabling or deleting the last active administrator is refused (400), as is a change that would lock out enforced SSO. " +
          "Every role change is recorded in the audit log.",
        operationId: "updateUser",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  name: { type: ["string", "null"] },
                  email: {
                    type: "string",
                    description:
                      "Changing it leaves username unchanged. Fails with 400 when another account has it (in any case) or signs " +
                      "in with it as username (for a @localhost address, also with the part before it)",
                  },
                  username: {
                    type: "string",
                    description:
                      "Username for the login page, which signs in by username only, ignoring case. Surrounding whitespace is removed; " +
                      "the rest must be 3-255 characters of lowercase letters (a-z), digits and _ . @ -, and must not be another " +
                      "account's username, email address or forward-auth portal name (the email <name>@localhost), compared " +
                      "case-insensitively. The username the user already has is no change. Otherwise the request fails with 400. " +
                      "A request refused with 400 changes no field.",
                  },
                  role: {
                    type: "string",
                    enum: ["admin", "user", "viewer"],
                    description: "A built-in role; also takes a custom role away. Any other value is ignored. With customRoleId, omit it or send viewer.",
                  },
                  customRoleId: {
                    type: ["integer", "null"],
                    description:
                      "A custom role id to assign it (the user is stored with role viewer), or null to take the custom role away " +
                      "(the user falls back to viewer unless role names another built-in role). Omit to leave the role as it is.",
                  },
                  status: { type: "string", enum: ["active", "disabled"] },
                },
              },
            },
          },
        },
        responses: {
          "200": {
            description: "User updated",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/User" },
              },
            },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": {
            description:
              "Missing users:write, or a user or role the caller may not manage or grant",
            content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } },
          },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },

    // ── Roles ───────────────────────────────────────────────────────
    "/api/v1/roles": {
      get: {
        tags: ["Roles"],
        summary: "List custom roles",
        description: "Permission users:read.",
        operationId: "listCustomRoles",
        responses: {
          "200": {
            description: "Custom roles, by name",
            content: {
              "application/json": {
                schema: { type: "array", items: { $ref: "#/components/schemas/CustomRole" } },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
      post: {
        tags: ["Roles"],
        summary: "Create a custom role",
        description:
          "Permission users:write. A caller can only put permissions they hold " +
          "into a role, and a scoped caller only a scope made of their own tags; only administrators create administrator-level " +
          "roles (403). Write, restore and import permissions also grant the area's read permission. A role with scopeTags " +
          "cannot hold the permissions that act on every host at once (unscopedOnly in GET /api/v1/permissions; 400). " +
          "Recorded in the audit log.",
        operationId: "createCustomRole",
        requestBody: {
          required: true,
          content: { "application/json": { schema: { $ref: "#/components/schemas/CustomRoleInput" } } },
        },
        responses: {
          "201": {
            description: "Role created",
            content: { "application/json": { schema: { $ref: "#/components/schemas/CustomRole" } } },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": {
            description: "Missing users:write, or permissions the caller may not grant",
            content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } },
          },
          "409": {
            description: "A role with this name (ignoring case) already exists",
            content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } },
          },
        },
      },
    },
    "/api/v1/roles/{id}": {
      get: {
        tags: ["Roles"],
        summary: "Get a custom role",
        description: "Permission users:read.",
        operationId: "getCustomRole",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": {
            description: "Custom role",
            content: { "application/json": { schema: { $ref: "#/components/schemas/CustomRole" } } },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      put: {
        tags: ["Roles"],
        summary: "Change a custom role",
        description:
          "Permission users:write. Fields left out keep their value. The same " +
          "escalation rules as creating a role apply to the role as it is and as it becomes; nobody changes the role they " +
          "have themselves (403). The change applies at once to the role's users and their API tokens. Recorded in the audit log.",
        operationId: "updateCustomRole",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        requestBody: {
          required: true,
          content: { "application/json": { schema: { $ref: "#/components/schemas/CustomRoleInput" } } },
        },
        responses: {
          "200": {
            description: "Role changed",
            content: { "application/json": { schema: { $ref: "#/components/schemas/CustomRole" } } },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": {
            description:
              "Missing users:write, a role or permissions the caller may not grant, or the caller's own role",
            content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } },
          },
          "404": { $ref: "#/components/responses/NotFound" },
          "409": {
            description: "Another role has this name (ignoring case)",
            content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } },
          },
        },
      },
      delete: {
        tags: ["Roles"],
        summary: "Delete a custom role",
        description:
          "Permission users:write. The role's users fall back to the built-in viewer role in the same " +
          "transaction; the deletion and each user's fallback are recorded in the audit log. A non-administrator can only delete " +
          "a role whose permissions they hold, and never the role they have themselves (403).",
        operationId: "deleteCustomRole",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": {
            description: "Role deleted",
            content: { "application/json": { schema: { $ref: "#/components/schemas/CustomRoleDeleteResult" } } },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },
    "/api/v1/permissions": {
      get: {
        tags: ["Roles"],
        summary: "Get the permission catalogue",
        description: "Permission users:read. Every permission a custom role can hold, by area, and the rules on granting them.",
        operationId: "getPermissionCatalogue",
        responses: {
          "200": {
            description: "Permission catalogue",
            content: { "application/json": { schema: { $ref: "#/components/schemas/PermissionCatalogue" } } },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },

    // ── Audit Log ───────────────────────────────────────────────────
    "/api/v1/audit-log": {
      get: {
        tags: ["Audit Log"],
        summary: "List audit log events",
        operationId: "listAuditLog",
        parameters: [
          {
            name: "page",
            in: "query",
            schema: { type: "integer", default: 1 },
            description: "Page number",
          },
          {
            name: "per_page",
            in: "query",
            schema: { type: "integer", default: 50 },
            description: "Items per page",
          },
          {
            name: "search",
            in: "query",
            schema: { type: "string", maxLength: 200 },
            description: "Text matched literally against the summary, the action and the entity type",
          },
          { name: "actor", in: "query", schema: { type: "string" }, description: 'A user id, or "system" for events no user recorded' },
          { name: "action", in: "query", schema: { type: "string" }, description: "Exact action, e.g. update or proxy_host_updated" },
          { name: "entityType", in: "query", schema: { type: "string" }, description: "Exact entity type, e.g. proxy_host" },
          { name: "entityId", in: "query", schema: { type: "integer" }, description: "Entity id (with entityType)" },
          { name: "from", in: "query", schema: { type: "string" }, description: "Earliest createdAt (ISO 8601 date or date-time, inclusive)" },
          { name: "to", in: "query", schema: { type: "string" }, description: "Latest createdAt (inclusive; a bare date includes that whole day)" },
        ],
        description:
          "Newest first. Every filter is optional and they combine. Each event names who acted, " +
          "its hash chain fields and, for a configuration change recorded while configuration history was on, " +
          "the history versions around it (configChange); GET /api/v1/audit-log/{id} returns the before/after diff.",
        responses: {
          "400": { $ref: "#/components/responses/BadRequest" },
          "200": {
            description: "Paginated audit log",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/AuditLogResponse" },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
    },

    // ── Audit Streaming ─────────────────────────────────────────────
    "/api/v1/audit-log/export": {
      get: {
        tags: ["Audit Streaming"],
        summary: "Export the audit log",
        description:
          "Streams the audit log in id order as a CSV or JSON download, including the hash chain fields so the copy can be verified offline. " +
          "CSV cells starting with = + - @, a tab or a carriage return are prefixed with an apostrophe. " +
          "Every export is recorded in the audit log.",
        operationId: "exportAuditLog",
        parameters: [
          { name: "format", in: "query", schema: { type: "string", enum: ["csv", "json"], default: "csv" } },
          {
            name: "from",
            in: "query",
            schema: { type: "string" },
            description: "Earliest createdAt to include (ISO 8601 date or date-time, inclusive)",
          },
          {
            name: "to",
            in: "query",
            schema: { type: "string" },
            description: "Latest createdAt to include (inclusive; a bare date includes that whole day)",
          },
        ],
        responses: {
          "200": {
            description: "The export, as an attachment",
            content: {
              "text/csv": {
                schema: {
                  type: "string",
                  description: "Header row: id,createdAt,userId,userEmail,userName,action,entityType,entityId,summary,data,prevHash,hash,actorDigest",
                },
              },
              "application/json": { schema: { $ref: "#/components/schemas/AuditLogExport" } },
            },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },
    "/api/v1/audit-log/verify": {
      get: {
        tags: ["Audit Streaming"],
        summary: "Verify the audit log hash chain",
        description:
          "Recomputes the hash chain from the oldest remaining chained event (its prevHash is the anchor, since retention deletes older events) to the newest. " +
          "Every check is recorded in the audit log.",
        operationId: "verifyAuditLog",
        responses: {
          "200": {
            description: "Verification result",
            content: { "application/json": { schema: { $ref: "#/components/schemas/AuditVerification" } } },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },
    "/api/v1/audit-log/retention": {
      get: {
        tags: ["Audit Streaming"],
        summary: "Get the audit log retention",
        operationId: "getAuditRetention",
        responses: {
          "200": {
            description: "Retention setting and last run",
            content: { "application/json": { schema: { $ref: "#/components/schemas/AuditRetention" } } },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
      put: {
        tags: ["Audit Streaming"],
        summary: "Set the audit log retention",
        description:
          "A daily job deletes events older than `days` (0 keeps them forever). Not synced to slaves.",
        operationId: "setAuditRetention",
        requestBody: {
          required: true,
          content: { "application/json": { schema: { $ref: "#/components/schemas/AuditRetentionInput" } } },
        },
        responses: {
          "200": {
            description: "Saved",
            content: { "application/json": { schema: { $ref: "#/components/schemas/AuditRetention" } } },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },
    "/api/v1/audit-sinks": {
      get: {
        tags: ["Audit Streaming"],
        summary: "List audit streaming sinks",
        description: "Secrets are never returned (see hasSecret).",
        operationId: "listAuditSinks",
        responses: {
          "200": {
            description: "Sinks",
            content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/AuditSink" } } } },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
      post: {
        tags: ["Audit Streaming"],
        summary: "Create an audit streaming sink",
        description:
          "New sinks receive events recorded from now on; set backfill to also deliver every event still in the log. Not synced to slaves.",
        operationId: "createAuditSink",
        requestBody: {
          required: true,
          content: { "application/json": { schema: { $ref: "#/components/schemas/AuditSinkInput" } } },
        },
        responses: {
          "201": {
            description: "Created",
            content: { "application/json": { schema: { $ref: "#/components/schemas/AuditSink" } } },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },
    "/api/v1/audit-sinks/{id}": {
      get: {
        tags: ["Audit Streaming"],
        summary: "Get an audit streaming sink",
        operationId: "getAuditSink",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": {
            description: "Sink",
            content: { "application/json": { schema: { $ref: "#/components/schemas/AuditSink" } } },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      put: {
        tags: ["Audit Streaming"],
        summary: "Update an audit streaming sink",
        description:
          "Fields left out keep their values; config is merged into the stored config. Omit secret to keep it. The type cannot be changed.",
        operationId: "updateAuditSink",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        requestBody: {
          required: true,
          content: { "application/json": { schema: { $ref: "#/components/schemas/AuditSinkUpdate" } } },
        },
        responses: {
          "200": {
            description: "Updated",
            content: { "application/json": { schema: { $ref: "#/components/schemas/AuditSink" } } },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      delete: {
        tags: ["Audit Streaming"],
        summary: "Delete an audit streaming sink",
        operationId: "deleteAuditSink",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "204": { description: "Deleted" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },
    "/api/v1/audit-sinks/{id}/test": {
      post: {
        tags: ["Audit Streaming"],
        summary: "Send a test event to an audit streaming sink",
        description:
          "Delivers one synthetic event (\"test\": true, id 0) and reports whether the receiver accepted it. The delivery cursor is not changed.",
        operationId: "testAuditSink",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": {
            description: "Result of the delivery attempt",
            content: { "application/json": { schema: { $ref: "#/components/schemas/AuditSinkTestResult" } } },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },

    // ── SSO ─────────────────────────────────────────────────────────
    "/api/v1/sso/enforcement": {
      get: {
        tags: ["SSO"],
        summary: "Get the enforced SSO setting",
        description:
          "Whether password sign-in to the dashboard is limited to break-glass accounts, which accounts those are, and the identity providers that stay open.",
        operationId: "getSsoEnforcement",
        responses: {
          "200": {
            description: "Enforced SSO setting",
            content: { "application/json": { schema: { $ref: "#/components/schemas/SsoEnforcement" } } },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
      put: {
        tags: ["SSO"],
        summary: "Change the enforced SSO setting",
        description:
          "Turning enforcement on, or changing it while on, is refused with 400 unless an OAuth/OIDC or SAML provider is enabled. " +
          "Break-glass accounts are optional (an empty list is accepted); every listed username must belong to an account that can sign in with a password. The change is recorded in the audit log.",
        operationId: "updateSsoEnforcement",
        requestBody: {
          required: true,
          content: { "application/json": { schema: { $ref: "#/components/schemas/SsoEnforcementInput" } } },
        },
        responses: {
          "200": {
            description: "Saved",
            content: { "application/json": { schema: { $ref: "#/components/schemas/SsoEnforcement" } } },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": {
            description: "Not an administrator",
            content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } },
          },
        },
      },
    },

    // ── MFA ─────────────────────────────────────────────────────────
    "/api/v1/mfa": {
      get: {
        tags: ["MFA"],
        summary: "Get your multi-factor authentication state",
        description: "Whether MFA is on for the caller, how many backup codes are left, and what the MFA policy asks of the account. Never returns the authenticator secret or backup codes.",
        operationId: "getOwnMfaStatus",
        responses: {
          "200": {
            description: "MFA state",
            content: { "application/json": { schema: { $ref: "#/components/schemas/MfaStatus" } } },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": {
            description: "The session's account must set up MFA first (the MFA policy's grace period is over)",
            content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } },
          },
        },
      },
    },
    "/api/v1/mfa/policy": {
      get: {
        tags: ["MFA"],
        summary: "Get the MFA policy",
        description: "Who must use MFA for dashboard sign-in, the grace period, and the covered accounts that have not set it up yet. Administrators only.",
        operationId: "getMfaPolicy",
        responses: {
          "200": {
            description: "MFA policy",
            content: { "application/json": { schema: { $ref: "#/components/schemas/MfaPolicy" } } },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
      put: {
        tags: ["MFA"],
        summary: "Change the MFA policy",
        description:
          "Require MFA for administrators or for every account that can sign in with a password. Accounts that sign in only through an identity provider are never covered, " +
          "and neither are accounts enforced SSO keeps from signing in with a password. Covered accounts without MFA are asked to set it up at sign-in; after the grace period " +
          "their dashboard sessions can only set it up. The grace period starts when the scope changes. Not synchronized to sync slaves. Recorded in the audit log as mfa_policy_updated.",
        operationId: "updateMfaPolicy",
        requestBody: {
          required: true,
          content: { "application/json": { schema: { $ref: "#/components/schemas/MfaPolicyInput" } } },
        },
        responses: {
          "200": {
            description: "Saved",
            content: { "application/json": { schema: { $ref: "#/components/schemas/MfaPolicy" } } },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },
    "/api/v1/users/{id}/mfa": {
      get: {
        tags: ["MFA"],
        summary: "Get a user's MFA state",
        description: "Administrators, or the user themself. Never returns the authenticator secret or backup codes.",
        operationId: "getUserMfaStatus",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": {
            description: "MFA state",
            content: { "application/json": { schema: { $ref: "#/components/schemas/MfaStatus" } } },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      delete: {
        tags: ["MFA"],
        summary: "Reset a user's MFA",
        description:
          "Turns MFA off for another user (for example after they lost their authenticator and backup codes): removes the authenticator secret, the backup codes and the sign-in lockout. " +
          "The user signs in with the password alone and can set MFA up again; their sessions are kept. Refused with 400 for your own account (turn it off from Profile, with your password). " +
          "Recorded in the audit log as mfa_reset.",
        operationId: "resetUserMfa",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": {
            description: "The user's MFA state after the reset",
            content: { "application/json": { schema: { $ref: "#/components/schemas/MfaStatus" } } },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },

    // ── Configuration History ───────────────────────────────────────
    "/api/v1/config-history": {
      get: {
        tags: ["Configuration History"],
        summary: "List configuration snapshots",
        description: "Newest first.",
        operationId: "listConfigSnapshots",
        parameters: [
          { name: "limit", in: "query", schema: { type: "integer", minimum: 1, maximum: 500, default: 50 } },
          { name: "offset", in: "query", schema: { type: "integer", minimum: 0, default: 0 } },
        ],
        responses: {
          "200": {
            description: "Snapshots",
            content: { "application/json": { schema: { $ref: "#/components/schemas/ConfigSnapshotList" } } },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
      post: {
        tags: ["Configuration History"],
        summary: "Create a manual snapshot",
        description:
          "Saves the current configuration as a snapshot, also when it equals the newest one. " +
          "Refused on a sync slave (409).",
        operationId: "createConfigSnapshot",
        requestBody: {
          required: false,
          content: {
            "application/json": {
              schema: {
                type: "object",
                additionalProperties: false,
                properties: { summary: { type: "string", maxLength: 200, description: "Optional note shown in the history" } },
              },
            },
          },
        },
        responses: {
          "201": {
            description: "Created",
            content: { "application/json": { schema: { $ref: "#/components/schemas/ConfigSnapshot" } } },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "409": { $ref: "#/components/responses/Conflict" },
        },
      },
      delete: {
        tags: ["Configuration History"],
        summary: "Delete all snapshots",
        operationId: "deleteAllConfigSnapshots",
        responses: {
          "200": {
            description: "Deleted",
            content: {
              "application/json": {
                schema: { type: "object", properties: { deleted: { type: "integer" } }, required: ["deleted"] },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },
    "/api/v1/config-history/settings": {
      get: {
        tags: ["Configuration History"],
        summary: "Get the configuration history settings",
        operationId: "getConfigHistorySettings",
        responses: {
          "200": {
            description: "Settings",
            content: { "application/json": { schema: { $ref: "#/components/schemas/ConfigHistorySettings" } } },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
      put: {
        tags: ["Configuration History"],
        summary: "Change the configuration history settings",
        description:
          "Turns automatic snapshots on or off and sets how many snapshots are kept (lowering it deletes older snapshots). " +
          "Turning it on records a first snapshot.",
        operationId: "updateConfigHistorySettings",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                additionalProperties: false,
                minProperties: 1,
                properties: {
                  enabled: { type: "boolean" },
                  retention: { type: "integer", minimum: 1, maximum: 10000 },
                },
              },
            },
          },
        },
        responses: {
          "200": {
            description: "Updated",
            content: { "application/json": { schema: { $ref: "#/components/schemas/ConfigHistorySettings" } } },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },
    "/api/v1/config-history/{id}": {
      get: {
        tags: ["Configuration History"],
        summary: "Get a snapshot",
        description: "The snapshot's metadata and a summary of its content (names and counts; no values, no secrets).",
        operationId: "getConfigSnapshot",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": {
            description: "Snapshot",
            content: { "application/json": { schema: { $ref: "#/components/schemas/ConfigSnapshotDetail" } } },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
          "409": { $ref: "#/components/responses/Conflict" },
        },
      },
      delete: {
        tags: ["Configuration History"],
        summary: "Delete a snapshot",
        operationId: "deleteConfigSnapshot",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "204": { description: "Deleted" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },
    "/api/v1/config-history/{id}/diff": {
      get: {
        tags: ["Configuration History"],
        summary: "Compare a snapshot",
        description:
          "Per entity type, the items added, removed and changed (with field-level changes) going from `against` to " +
          "the snapshot. With against=current this is what restoring the snapshot would change. Secret values are never " +
          "returned: their changes are reported with secret: true.",
        operationId: "diffConfigSnapshot",
        parameters: [
          { $ref: "#/components/parameters/IdPath" },
          {
            name: "against",
            in: "query",
            schema: { type: "string", default: "current" },
            description: '"current" (the current configuration), "previous" (the snapshot before this one) or a snapshot id',
          },
        ],
        responses: {
          "200": {
            description: "Differences",
            content: { "application/json": { schema: { $ref: "#/components/schemas/ConfigSnapshotDiff" } } },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
          "409": { $ref: "#/components/responses/Conflict" },
        },
      },
    },
    "/api/v1/config-history/{id}/restore": {
      post: {
        tags: ["Configuration History"],
        summary: "Restore a snapshot",
        description:
          "Replaces the configuration with the snapshot in one transaction, after saving the current configuration as a " +
          "before_restore snapshot, then applies it to Caddy. If Caddy rejects it, the previous configuration is put back (502). " +
          "Users, group memberships, sessions, API tokens and sign-in settings are never changed. Refused on a sync slave (409)." +
          REPLACEMENT_PROTECTED_NOTE,
        operationId: "restoreConfigSnapshot",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": {
            description: "Restored",
            content: { "application/json": { schema: { $ref: "#/components/schemas/ConfigRestoreResult" } } },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
          "409": { $ref: "#/components/responses/Conflict" },
          "502": { $ref: "#/components/responses/ConfigurationRejected" },
        },
      },
    },

    // ── Configuration export/import ─────────────────────────────────
    "/api/v1/config/export": {
      post: {
        tags: ["Configuration"],
        summary: "Export the configuration",
        description:
          "Downloads the configuration (proxy hosts, L4 proxy hosts, certificates, CA and client certificates, access lists, " +
          "mTLS roles and rules, forward-auth groups and grants, settings) as JSON. Secrets are encrypted with the passphrase " +
          "(scrypt, AES-256-GCM). Refused on a sync slave (409) and when a stored secret cannot be decrypted (409).",
        operationId: "exportConfiguration",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["passphrase"],
                properties: { passphrase: { type: "string", minLength: 12, maxLength: 1024 } },
              },
            },
          },
        },
        responses: {
          "200": {
            description: "The export file (Content-Disposition: attachment)",
            content: { "application/json": { schema: { $ref: "#/components/schemas/ConfigExportFile" } } },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "409": { $ref: "#/components/responses/Conflict" },
        },
      },
    },
    "/api/v1/config/import": {
      post: {
        tags: ["Configuration"],
        summary: "Import a configuration file",
        description:
          "Replaces the configuration with the one in an export file, like a restore, and applies it. The file is validated " +
          "and the passphrase checked before anything changes: a wrong passphrase is a 400 and changes nothing. When " +
          "configuration history is on, the configuration being replaced is saved as a snapshot (reason import) first. " +
          "Forward-auth grants for users are matched to local users by email address. Refused on a sync slave (409)." +
          REPLACEMENT_PROTECTED_NOTE,
        operationId: "importConfiguration",
        requestBody: {
          required: true,
          content: {
            "multipart/form-data": {
              schema: {
                type: "object",
                required: ["file", "passphrase"],
                properties: {
                  file: { type: "string", format: "binary" },
                  passphrase: { type: "string" },
                },
              },
            },
            "application/json": {
              schema: {
                type: "object",
                required: ["file", "passphrase"],
                properties: {
                  file: {
                    oneOf: [{ $ref: "#/components/schemas/ConfigExportFile" }, { type: "string", description: "The file as text" }],
                  },
                  passphrase: { type: "string" },
                },
              },
            },
          },
        },
        responses: {
          "200": {
            description: "Imported",
            content: { "application/json": { schema: { $ref: "#/components/schemas/ConfigImportResult" } } },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "409": { $ref: "#/components/responses/Conflict" },
          "413": { description: "The file is too large", content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } } },
          "502": { $ref: "#/components/responses/ConfigurationRejected" },
        },
      },
    },

    // ── Scheduled backups (ee) ──────────────────────────────────────
    "/api/v1/backup-destinations": {
      get: {
        tags: ["Backups"],
        summary: "List backup destinations",
        description: "The secret access key and the passphrase are never returned (see hasSecretAccessKey, hasPassphrase).",
        operationId: "listBackupDestinations",
        responses: {
          "200": {
            description: "Destinations",
            content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/BackupDestination" } } } },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
      post: {
        tags: ["Backups"],
        summary: "Create a backup destination",
        description:
          "Stores the secret access key and the export passphrase encrypted with this instance's key, so that backups run unattended. " +
          "Keep the passphrase in a password manager: restoring a backup on a new machine needs it. Refused on a sync slave (409). " +
          "Not synced to slaves.",
        operationId: "createBackupDestination",
        requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/BackupDestinationInput" } } } },
        responses: {
          "201": { description: "Created", content: { "application/json": { schema: { $ref: "#/components/schemas/BackupDestination" } } } },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "409": { $ref: "#/components/responses/Conflict" },
        },
      },
    },
    "/api/v1/backup-destinations/{id}": {
      get: {
        tags: ["Backups"],
        summary: "Get a backup destination",
        operationId: "getBackupDestination",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { description: "Destination", content: { "application/json": { schema: { $ref: "#/components/schemas/BackupDestination" } } } },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      put: {
        tags: ["Backups"],
        summary: "Update a backup destination",
        description:
          "Fields left out keep their values; an omitted or empty secretAccessKey or passphrase keeps the stored one. Changing the endpoint " +
          "requires entering the secret access key again. Changing the passphrase does not re-encrypt earlier backups: restoring them needs " +
          "the passphrase they were made with.",
        operationId: "updateBackupDestination",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/BackupDestinationUpdate" } } } },
        responses: {
          "200": { description: "Updated", content: { "application/json": { schema: { $ref: "#/components/schemas/BackupDestination" } } } },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      delete: {
        tags: ["Backups"],
        summary: "Delete a backup destination",
        description: "Deletes the destination and its run history; the backup files in the bucket are kept.",
        operationId: "deleteBackupDestination",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "204": { description: "Deleted" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },
    "/api/v1/backup-destinations/{id}/test": {
      post: {
        tags: ["Backups"],
        summary: "Test a backup destination",
        description:
          "Writes a small object under the prefix, reads it back and deletes it. Failures are reported in the body (200 with ok=false).",
        operationId: "testBackupDestination",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { description: "Test result", content: { "application/json": { schema: { $ref: "#/components/schemas/BackupTestResult" } } } },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },
    "/api/v1/backup-destinations/{id}/run": {
      post: {
        tags: ["Backups"],
        summary: "Back up now",
        description:
          "Builds the passphrase-encrypted export file (the same file as POST /api/v1/config/export), uploads it as " +
          "<prefix>/ingressi-config-<time>.json with Content-Type application/json and its SHA-256 (signed payload hash and " +
          "x-amz-meta-sha256), then deletes backup files beyond the retention. Returns the run; a failed upload is a 200 with " +
          "status \"failed\". 409 while a backup to the destination is running and on a sync slave.",
        operationId: "runBackup",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { description: "The run", content: { "application/json": { schema: { $ref: "#/components/schemas/BackupRun" } } } },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
          "409": { $ref: "#/components/responses/Conflict" },
        },
      },
    },
    "/api/v1/backup-destinations/{id}/objects": {
      get: {
        tags: ["Backups"],
        summary: "List stored backups",
        description:
          "Backup files directly under the destination's prefix, newest first (at most 1000). Other objects are not listed. " +
          "502 when the storage request fails.",
        operationId: "listBackupObjects",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { description: "Backups", content: { "application/json": { schema: { $ref: "#/components/schemas/BackupObjectsListing" } } } },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
          "502": { description: "The storage request failed", content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } } },
        },
      },
    },
    "/api/v1/backup-destinations/{id}/restore": {
      post: {
        tags: ["Backups"],
        summary: "Restore a stored backup",
        description:
          "Downloads the backup, checks its SHA-256 against the stored checksum and imports it exactly like POST /api/v1/config/import: " +
          "validated and decrypted before anything changes (a wrong passphrase is a 400), the replaced configuration saved as a history " +
          "snapshot when configuration history is on, 502 and nothing changed if Caddy rejects it or the storage request fails. Uses the " +
          "destination's passphrase unless one is given (for backups made before it changed). Refused " +
          "on a sync slave (409)." + REPLACEMENT_PROTECTED_NOTE,
        operationId: "restoreBackup",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/BackupRestoreInput" } } } },
        responses: {
          "200": { description: "Restored", content: { "application/json": { schema: { $ref: "#/components/schemas/BackupRestoreResult" } } } },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
          "409": { $ref: "#/components/responses/Conflict" },
          "502": { description: "Caddy rejected the configuration or the storage request failed; nothing was changed", content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } } },
        },
      },
    },
    "/api/v1/backup-runs": {
      get: {
        tags: ["Backups"],
        summary: "List backup runs",
        description: "Scheduled and manual backup attempts, newest first; the newest 200 per destination are kept.",
        operationId: "listBackupRuns",
        parameters: [
          { name: "page", in: "query", schema: { type: "integer", minimum: 1, default: 1 } },
          { name: "per_page", in: "query", schema: { type: "integer", minimum: 1, maximum: 200, default: 50 } },
          { name: "destination_id", in: "query", schema: { type: "integer" }, description: "Only runs of this destination" },
        ],
        responses: {
          "200": { description: "A page of runs", content: { "application/json": { schema: { $ref: "#/components/schemas/BackupRunsResponse" } } } },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },

    // ── Alerting (ee) ───────────────────────────────────────────────
    "/api/v1/alert-channels": {
      get: {
        tags: ["Alerting"],
        summary: "List alert channels",
        description: "Credentials are never returned: secret fields are replaced by `has*` flags, URLs by their scheme and host.",
        operationId: "listAlertChannels",
        responses: {
          "200": { description: "Alert channels", content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/AlertChannel" } } } } },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
      post: {
        tags: ["Alerting"],
        summary: "Create an alert channel",
        operationId: "createAlertChannel",
        requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/AlertChannelInput" } } } },
        responses: {
          "201": { description: "Created", content: { "application/json": { schema: { $ref: "#/components/schemas/AlertChannel" } } } },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },
    "/api/v1/alert-channels/{id}": {
      get: {
        tags: ["Alerting"],
        summary: "Get an alert channel",
        operationId: "getAlertChannel",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { description: "Alert channel", content: { "application/json": { schema: { $ref: "#/components/schemas/AlertChannel" } } } },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      put: {
        tags: ["Alerting"],
        summary: "Update an alert channel",
        description:
          "Omitted fields keep their value. In `config`, an omitted or empty secret keeps the stored one and null removes an optional one. " +
          "Changing the SMTP host or the ntfy server requires entering the password or token again. The type cannot be changed.",
        operationId: "updateAlertChannel",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/AlertChannelUpdate" } } } },
        responses: {
          "200": { description: "Updated", content: { "application/json": { schema: { $ref: "#/components/schemas/AlertChannel" } } } },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      delete: {
        tags: ["Alerting"],
        summary: "Delete an alert channel",
        description: "Refused with 409 while a rule notifies the channel.",
        operationId: "deleteAlertChannel",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "204": { description: "Deleted" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
          "409": { description: "The channel is used by a rule", content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } } },
        },
      },
    },
    "/api/v1/alert-channels/test": {
      post: {
        tags: ["Alerting"],
        summary: "Test a channel before saving it",
        description: "Sends a test notification to the channel described by the body (as for creating one) without saving it. Delivery failures are reported in the body (200 with ok=false).",
        operationId: "testNewAlertChannel",
        requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/AlertChannelInput" } } } },
        responses: {
          "200": { description: "Delivery result", content: { "application/json": { schema: { $ref: "#/components/schemas/AlertDeliveryResult" } } } },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },
    "/api/v1/alert-channels/{id}/test": {
      post: {
        tags: ["Alerting"],
        summary: "Send a test notification",
        description:
          "Without a body, tests the stored channel. With a body (name and config fields, as for an update), tests the channel with those changes over its stored credentials, without saving them. Delivery failures are reported in the body (200 with ok=false).",
        operationId: "testAlertChannel",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        requestBody: { required: false, content: { "application/json": { schema: { $ref: "#/components/schemas/AlertChannelInput" } } } },
        responses: {
          "200": { description: "Delivery result", content: { "application/json": { schema: { $ref: "#/components/schemas/AlertDeliveryResult" } } } },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },
    "/api/v1/alert-rules": {
      get: {
        tags: ["Alerting"],
        summary: "List alert rules",
        description: "Each rule lists the subjects currently firing.",
        operationId: "listAlertRules",
        responses: {
          "200": { description: "Alert rules", content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/AlertRule" } } } } },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
      post: {
        tags: ["Alerting"],
        summary: "Create an alert rule",
        operationId: "createAlertRule",
        requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/AlertRuleInput" } } } },
        responses: {
          "201": { description: "Created", content: { "application/json": { schema: { $ref: "#/components/schemas/AlertRule" } } } },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },
    "/api/v1/alert-rules/{id}": {
      get: {
        tags: ["Alerting"],
        summary: "Get an alert rule",
        operationId: "getAlertRule",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { description: "Alert rule", content: { "application/json": { schema: { $ref: "#/components/schemas/AlertRule" } } } },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      put: {
        tags: ["Alerting"],
        summary: "Update an alert rule",
        description:
          "Omitted fields keep their value; params are merged. The type cannot be changed. Disabling a rule forgets what was firing.",
        operationId: "updateAlertRule",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/AlertRuleUpdate" } } } },
        responses: {
          "200": { description: "Updated", content: { "application/json": { schema: { $ref: "#/components/schemas/AlertRule" } } } },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      delete: {
        tags: ["Alerting"],
        summary: "Delete an alert rule",
        description: "The rule's history is kept. Built-in rules (builtIn set) cannot be deleted; disable them instead (409).",
        operationId: "deleteAlertRule",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "204": { description: "Deleted" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
          "409": { $ref: "#/components/responses/Conflict" },
        },
      },
    },
    "/api/v1/alert-events": {
      get: {
        tags: ["Alerting"],
        summary: "List alert history",
        description: "Firing and resolved transitions, newest first. Kept for 90 days.",
        operationId: "listAlertEvents",
        parameters: [
          { name: "page", in: "query", schema: { type: "integer", minimum: 1, default: 1 } },
          { name: "per_page", in: "query", schema: { type: "integer", minimum: 1, maximum: 200, default: 50 } },
          { name: "rule_id", in: "query", schema: { type: "integer" }, description: "Only events of this rule" },
        ],
        responses: {
          "200": { description: "A page of events", content: { "application/json": { schema: { $ref: "#/components/schemas/AlertEventsResponse" } } } },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },
    "/api/v1/alert-silences": {
      get: {
        tags: ["Alerting"],
        summary: "List alert mutes and dismissals",
        description:
          "The mutes (a whole rule, until a time) and dismissals (one alert, until a time or until it resolves) in effect, newest first. " +
          "Dismissed alerts and alerts of muted rules stay in /api/v1/alert-events/firing, marked, and are left out of the overview's " +
          "\"needs attention\" list and the sidebar count. Permission alerts:read.",
        operationId: "listAlertSilences",
        responses: {
          "200": { description: "Mutes and dismissals", content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/AlertSilence" } } } } },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
      post: {
        tags: ["Alerting"],
        summary: "Dismiss an alert or mute a rule",
        description:
          "With a subjectKey, dismisses that alert of the rule; without one, mutes every alert of the rule. Give until or durationMinutes " +
          "(at most 30 days); without either, the dismissal lasts until the alert resolves, which needs it to be firing now (409 otherwise). " +
          "A mute always needs one. While covered, an alert that starts firing is recorded in the history as not notified (silenced) and " +
          "sends nothing, so no resolve notice follows either; notifications already sent are not taken back. A new dismissal of the same " +
          "alert, or a new mute of the same rule, replaces the previous one. Permission alerts:write.",
        operationId: "createAlertSilence",
        requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/AlertSilenceInput" } } } },
        responses: {
          "201": { description: "Created", content: { "application/json": { schema: { $ref: "#/components/schemas/AlertSilence" } } } },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "409": { description: "Dismissing until it resolves an alert that is not firing", content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } } },
        },
      },
    },
    "/api/v1/alert-silences/{id}": {
      delete: {
        tags: ["Alerting"],
        summary: "Undo a dismissal or mute",
        description: "Permission alerts:write.",
        operationId: "deleteAlertSilence",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "204": { description: "Removed" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },

    // ── AI analyst (ee) ─────────────────────────────────────────────
    "/api/v1/ai/settings": {
      get: {
        tags: ["AI"],
        summary: "Get the AI provider settings",
        description: "The API key is never returned.",
        operationId: "getAiSettings",
        responses: {
          "200": { description: "AI provider settings", content: { "application/json": { schema: { $ref: "#/components/schemas/AiSettings" } } } },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
      put: {
        tags: ["AI"],
        summary: "Set the AI provider",
        description:
          "{\"provider\": null} removes the provider, and a body of only " +
          "{\"enabled\": false} and/or {\"apiKey\": null} switches it off. Omitted fields keep their value; an omitted or empty apiKey keeps the stored key, null removes it. " +
          "Changing the provider or base URL requires entering the key again, so a key is only ever sent to the provider it was entered for.",
        operationId: "updateAiSettings",
        requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/AiSettingsInput" } } } },
        responses: {
          "200": { description: "Saved", content: { "application/json": { schema: { $ref: "#/components/schemas/AiSettings" } } } },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
      delete: {
        tags: ["AI"],
        summary: "Remove the AI provider",
        description: "Deletes the provider settings and the stored key.",
        operationId: "deleteAiSettings",
        responses: {
          "204": { description: "Removed" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },
    "/api/v1/ai/test": {
      post: {
        tags: ["AI"],
        summary: "Test the AI provider",
        description: "Asks the configured model to explain a sample alert. Provider failures are reported in the body.",
        operationId: "testAiProvider",
        responses: {
          "200": { description: "Result", content: { "application/json": { schema: { $ref: "#/components/schemas/AiTestResult" } } } },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },

    "/api/v1/ai/digest": {
      get: {
        tags: ["AI"],
        summary: "Get the daily security digest settings",
        description: "Always available to administrators. Includes the next scheduled send and the result of the last run.",
        operationId: "getAiDigestSettings",
        responses: {
          "200": { description: "Digest settings", content: { "application/json": { schema: { $ref: "#/components/schemas/AiDigestSettings" } } } },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
      put: {
        tags: ["AI"],
        summary: "Configure the daily security digest",
        description:
          "Omitted fields keep their value. channelIds are alert channel ids; PagerDuty channels do not receive digests. " +
          "Enabling the digest or changing its time never sends a slot that has already passed today. Not synced to slave instances.",
        operationId: "updateAiDigestSettings",
        requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/AiDigestSettingsInput" } } } },
        responses: {
          "200": { description: "Saved", content: { "application/json": { schema: { $ref: "#/components/schemas/AiDigestSettings" } } } },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },
    "/api/v1/ai/digest/preview": {
      post: {
        tags: ["AI"],
        summary: "Preview the daily security digest",
        description:
          "Builds the digest for the last 24 hours and returns it rendered (e-mail subject, plain text and HTML) without sending it. " +
          "With AI on and a provider configured, the model is asked for the narrative; a failure is reported in narrative and the plain digest is returned.",
        operationId: "previewAiDigest",
        requestBody: {
          required: false,
          content: { "application/json": { schema: { type: "object", additionalProperties: false, properties: { ai: { type: "boolean", description: "Override the saved ai setting for this preview" } } } } },
        },
        responses: {
          "200": { description: "Rendered digest", content: { "application/json": { schema: { $ref: "#/components/schemas/AiDigestPreview" } } } },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },
    "/api/v1/ai/digest/send": {
      post: {
        tags: ["AI"],
        summary: "Send the daily security digest now",
        description: "Sends the digest to its enabled channels now, whether or not the schedule is on. Delivery failures are reported per channel.",
        operationId: "sendAiDigest",
        responses: {
          "200": { description: "Result", content: { "application/json": { schema: { $ref: "#/components/schemas/AiDigestSendResult" } } } },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },
    "/api/v1/waf/tuning-suggestions": {
      get: {
        tags: ["AI"],
        summary: "Generate WAF tuning suggestions",
        description:
          "Looks for likely WAF false positives in the WAF events of the last 14 days (or the ClickHouse retention, if shorter): the same rule matching on the same host " +
          "for many different clients over several days, mostly without blocking or with a low anomaly score, from clients that otherwise behave normally. " +
          "Each suggestion proposes suppressing the rule for that proxy host and carries its evidence. Replaces the open suggestions; dismissed ones are not proposed again. " +
          "Nothing is applied automatically. Needs ClickHouse analytics.",
        operationId: "listWafTuningSuggestions",
        parameters: [
          { name: "explain", in: "query", required: false, schema: { type: "boolean", default: false }, description: "Ask the configured model for a risk assessment of up to 5 suggestions that have none" },
        ],
        responses: {
          "200": { description: "Suggestions, highest confidence first", content: { "application/json": { schema: { $ref: "#/components/schemas/WafTuningResult" } } } },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
        },
      },
    },
    "/api/v1/waf/tuning-suggestions/{id}/apply": {
      post: {
        tags: ["AI"],
        summary: "Apply a WAF tuning suggestion",
        description:
          "Adds the rule to the excluded rules of the suggestion's proxy host, exactly like \"Suppress for host\" on the WAF page, and applies the configuration. Recorded in the audit log.",
        operationId: "applyWafTuningSuggestion",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
        responses: {
          "200": { description: "Applied", content: { "application/json": { schema: { $ref: "#/components/schemas/WafTuningApplyResult" } } } },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
          "409": { $ref: "#/components/responses/Conflict" },
        },
      },
    },
    "/api/v1/waf/tuning-suggestions/{id}/dismiss": {
      post: {
        tags: ["AI"],
        summary: "Dismiss a WAF tuning suggestion",
        description: "Remembers the dismissal so the suggestion is not proposed again. Recorded in the audit log.",
        operationId: "dismissWafTuningSuggestion",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
        responses: {
          "200": { description: "Dismissed", content: { "application/json": { schema: { $ref: "#/components/schemas/WafTuningSuggestion" } } } },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "403": { $ref: "#/components/responses/Forbidden" },
          "404": { $ref: "#/components/responses/NotFound" },
          "409": { $ref: "#/components/responses/Conflict" },
        },
      },
    },

    // ── Groups ──────────────────────────────────────────────────────
    "/api/v1/groups": {
      get: {
        tags: ["Groups"],
        summary: "List groups",
        operationId: "listGroups",
        responses: {
          "200": { description: "List of groups", content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/Group" } } } } },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
      post: {
        tags: ["Groups"],
        summary: "Create a group",
        operationId: "createGroup",
        requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["name"], properties: { name: { type: "string", minLength: 1, maxLength: 100, description: "Trimmed; unique" }, description: { type: ["string", "null"], maxLength: 500 } } } } } },
        responses: {
          "201": { description: "Group created", content: { "application/json": { schema: { $ref: "#/components/schemas/Group" } } } },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "409": { $ref: "#/components/responses/Conflict" },
        },
      },
    },
    "/api/v1/groups/{id}": {
      get: {
        tags: ["Groups"],
        summary: "Get a group",
        operationId: "getGroup",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { description: "Group details", content: { "application/json": { schema: { $ref: "#/components/schemas/Group" } } } },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      patch: {
        tags: ["Groups"],
        summary: "Update a group",
        operationId: "updateGroup",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        requestBody: { required: true, content: { "application/json": { schema: { type: "object", properties: { name: { type: "string", minLength: 1, maxLength: 100, description: "Trimmed; unique" }, description: { type: ["string", "null"], maxLength: 500 } } } } } },
        responses: {
          "200": { description: "Group updated", content: { "application/json": { schema: { $ref: "#/components/schemas/Group" } } } },
          "400": { $ref: "#/components/responses/BadRequest" },
          "404": { $ref: "#/components/responses/NotFound" },
          "409": { $ref: "#/components/responses/Conflict" },
        },
      },
      delete: {
        tags: ["Groups"],
        summary: "Delete a group",
        operationId: "deleteGroup",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { $ref: "#/components/responses/Ok" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },
    "/api/v1/groups/{id}/members": {
      post: {
        tags: ["Groups"],
        summary: "Add a member to a group",
        operationId: "addGroupMember",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["userId"], properties: { userId: { type: "integer" } } } } } },
        responses: {
          "200": { $ref: "#/components/responses/Ok" },
          "404": { $ref: "#/components/responses/NotFound" },
          "409": { $ref: "#/components/responses/Conflict" },
        },
      },
    },
    "/api/v1/groups/{id}/members/{userId}": {
      delete: {
        tags: ["Groups"],
        summary: "Remove a member from a group",
        operationId: "removeGroupMember",
        parameters: [
          { $ref: "#/components/parameters/IdPath" },
          { name: "userId", in: "path", required: true, schema: { type: "integer" }, description: "User ID to remove" },
        ],
        responses: {
          "200": { $ref: "#/components/responses/Ok" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },

    // ── mTLS Roles ─────────────────────────────────────────────────
    "/api/v1/mtls-roles": {
      get: {
        tags: ["mTLS Roles"],
        summary: "List mTLS roles",
        operationId: "listMtlsRoles",
        responses: {
          "200": { description: "List of roles", content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/MtlsRole" } } } } },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
      post: {
        tags: ["mTLS Roles"],
        summary: "Create an mTLS role",
        operationId: "createMtlsRole",
        requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["name"], properties: { name: { type: "string" }, description: { type: "string" } } } } } },
        responses: {
          "201": { description: "Role created", content: { "application/json": { schema: { $ref: "#/components/schemas/MtlsRole" } } } },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
    },
    "/api/v1/mtls-roles/{id}": {
      get: {
        tags: ["mTLS Roles"],
        summary: "Get an mTLS role",
        operationId: "getMtlsRole",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { description: "Role details", content: { "application/json": { schema: { $ref: "#/components/schemas/MtlsRole" } } } },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      put: {
        tags: ["mTLS Roles"],
        summary: "Update an mTLS role",
        operationId: "updateMtlsRole",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        requestBody: { required: true, content: { "application/json": { schema: { type: "object", properties: { name: { type: "string" }, description: { type: "string" } } } } } },
        responses: {
          "200": { description: "Role updated", content: { "application/json": { schema: { $ref: "#/components/schemas/MtlsRole" } } } },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      delete: {
        tags: ["mTLS Roles"],
        summary: "Delete an mTLS role",
        operationId: "deleteMtlsRole",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { $ref: "#/components/responses/Ok" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },
    "/api/v1/mtls-roles/{id}/certificates": {
      post: {
        tags: ["mTLS Roles"],
        summary: "Assign a certificate to an mTLS role",
        operationId: "assignMtlsRoleCertificate",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["certificateId"], properties: { certificateId: { type: "integer" } } } } } },
        responses: {
          "200": { $ref: "#/components/responses/Ok" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },
    "/api/v1/mtls-roles/{id}/certificates/{certId}": {
      delete: {
        tags: ["mTLS Roles"],
        summary: "Remove a certificate from an mTLS role",
        operationId: "removeMtlsRoleCertificate",
        parameters: [
          { $ref: "#/components/parameters/IdPath" },
          { name: "certId", in: "path", required: true, schema: { type: "integer" }, description: "Client certificate ID" },
        ],
        responses: {
          "200": { $ref: "#/components/responses/Ok" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },

    // ── Forward Auth ───────────────────────────────────────────────
    "/api/v1/proxy-hosts/{id}/forward-auth-access": {
      get: {
        tags: ["Forward Auth"],
        summary: "Get forward auth access list for a proxy host",
        operationId: "getForwardAuthAccess",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { description: "Access list with user IDs and group IDs", content: { "application/json": { schema: { type: "object", properties: { userIds: { type: "array", items: { type: "integer" } }, groupIds: { type: "array", items: { type: "integer" } } } } } } },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      put: {
        tags: ["Forward Auth"],
        summary: "Set forward auth access list for a proxy host",
        description: "Permission proxy_hosts:write. Replaces the host's grants; users and groups that do not exist are left out, and ids that are not whole numbers are refused (400)." + PROTECTED_HOST_NOTE,
        operationId: "setForwardAuthAccess",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        requestBody: { required: true, content: { "application/json": { schema: { type: "object", properties: { userIds: { type: "array", items: { type: "integer" } }, groupIds: { type: "array", items: { type: "integer" } } } } } } },
        responses: {
          "200": { $ref: "#/components/responses/Ok" },
          "202": { $ref: "#/components/responses/ChangeRequestSubmitted" },
          "400": { $ref: "#/components/responses/BadRequest" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },
    "/api/v1/forward-auth-sessions": {
      get: {
        tags: ["Forward Auth"],
        summary: "List forward auth sessions",
        operationId: "listForwardAuthSessions",
        parameters: [{ name: "userId", in: "query", schema: { type: "integer" }, description: "Filter by user ID" }],
        responses: {
          "200": { description: "List of sessions", content: { "application/json": { schema: { type: "array", items: { type: "object" } } } } },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
      delete: {
        tags: ["Forward Auth"],
        summary: "Delete forward auth sessions",
        operationId: "deleteForwardAuthSessions",
        parameters: [{ name: "userId", in: "query", schema: { type: "integer" }, description: "Delete sessions for a specific user" }],
        responses: {
          "200": { $ref: "#/components/responses/Ok" },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
    },
    "/api/v1/forward-auth-sessions/{id}": {
      delete: {
        tags: ["Forward Auth"],
        summary: "Delete a specific forward auth session",
        operationId: "deleteForwardAuthSession",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { $ref: "#/components/responses/Ok" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },

    // ── Caddy ───────────────────────────────────────────────────────
    "/api/v1/caddy/apply": {
      post: {
        tags: ["Caddy"],
        summary: "Apply Caddy configuration",
        operationId: "applyCaddyConfig",
        responses: {
          "200": { $ref: "#/components/responses/Ok" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "500": { $ref: "#/components/responses/InternalError" },
        },
      },
    },

    // ── OAuth Providers ─────────────────────────────────────────────
    "/api/v1/oauth-providers": {
      get: {
        tags: ["OAuth Providers"],
        summary: "List OAuth providers",
        operationId: "listOauthProviders",
        responses: {
          "200": {
            description: "List of OAuth providers",
            content: {
              "application/json": {
                schema: {
                  type: "array",
                  items: { $ref: "#/components/schemas/OauthProvider" },
                },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
      post: {
        tags: ["OAuth Providers"],
        summary: "Create an OAuth provider",
        operationId: "createOauthProvider",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/OauthProviderInput" },
            },
          },
        },
        responses: {
          "201": {
            description: "OAuth provider created",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/OauthProvider" },
              },
            },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
        },
      },
    },
    "/api/v1/oauth-providers/{id}": {
      get: {
        tags: ["OAuth Providers"],
        summary: "Get an OAuth provider",
        operationId: "getOauthProvider",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": {
            description: "OAuth provider",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/OauthProvider" },
              },
            },
          },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      put: {
        tags: ["OAuth Providers"],
        summary: "Update an OAuth provider",
        description:
          "Environment-sourced providers only allow toggling `enabled`. A blank or omitted clientSecret preserves the stored secret.",
        operationId: "updateOauthProvider",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/OauthProviderUpdate" },
            },
          },
        },
        responses: {
          "200": {
            description: "OAuth provider updated",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/OauthProvider" },
              },
            },
          },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
      delete: {
        tags: ["OAuth Providers"],
        summary: "Delete an OAuth provider",
        description: "Environment-sourced providers cannot be deleted.",
        operationId: "deleteOauthProvider",
        parameters: [{ $ref: "#/components/parameters/IdPath" }],
        responses: {
          "200": { $ref: "#/components/responses/Ok" },
          "400": { $ref: "#/components/responses/BadRequest" },
          "401": { $ref: "#/components/responses/Unauthorized" },
          "404": { $ref: "#/components/responses/NotFound" },
        },
      },
    },
  },
  components: {
    securitySchemes: {
      bearerAuth: {
        type: "http",
        scheme: "bearer",
        description: "API token created from the Profile page",
      },
      sessionAuth: {
        type: "apiKey",
        in: "cookie",
        name: "authjs.session-token",
        description: "Cookie-based session from browser login",
      },
    },
    parameters: {
      IdPath: {
        name: "id",
        in: "path",
        required: true,
        schema: { type: "integer" },
        description: "Resource ID",
      },
      SyncKeyPinUrl: {
        name: "url",
        in: "query",
        required: true,
        schema: { type: "string" },
        example: "https://replica.example.com",
        description:
          "The slave base URL, compared after normalization (lowercase scheme and host, no default port, dot segments or trailing slashes); " +
          "the url GET /api/v1/instances/sync-key-pins lists works as is",
      },
    },
    responses: {
      Ok: {
        description: "Success",
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: { ok: { type: "boolean", enum: [true] } },
              required: ["ok"],
            },
          },
        },
      },
      BadRequest: {
        description: "Bad request",
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/Error" },
          },
        },
      },
      Unauthorized: {
        description: "Unauthorized",
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/Error" },
          },
        },
      },
      Forbidden: {
        description: "Forbidden",
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/Error" },
          },
        },
      },
      NotFound: {
        description: "Not found",
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/Error" },
          },
        },
      },
      Conflict: {
        description: "Conflict (for example: the instance is a sync slave)",
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/Error" },
          },
        },
      },
      ConfigurationRejected: {
        description: "Caddy did not accept the configuration; the previous configuration was put back",
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/Error" },
          },
        },
      },
      ChangeRequestSubmitted: CHANGE_REQUEST_SUBMITTED_RESPONSE,
      InternalError: {
        description: "Internal server error",
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/Error" },
          },
        },
      },
    },
    schemas: {
      ...ACCESS_LISTS_OPENAPI_SCHEMAS,
      ...MONETIZATION_OPENAPI_SCHEMAS,
      ...WHITE_LABEL_OPENAPI_SCHEMAS,
      ...APPROVALS_OPENAPI_SCHEMAS,
      ...COMPLIANCE_OPENAPI_SCHEMAS,
      ...LDAP_OPENAPI_SCHEMAS,
      ...SAML_OPENAPI_SCHEMAS,
      ...SCIM_OPENAPI_SCHEMAS,
      ...ACCESS_REVIEWS_OPENAPI_SCHEMAS,
      ...FLEET_OPENAPI_SCHEMAS,
      ...SEARCH_OPENAPI_SCHEMAS,
      ...ANALYTICS_OPENAPI_SCHEMAS,
      ...QUESTIONS_OPENAPI_SCHEMAS,
      ...WAF_OPENAPI_SCHEMAS,
      ...CERTIFICATE_OVERVIEW_OPENAPI_SCHEMAS,
      ...PROXY_HOST_HEALTH_OPENAPI_SCHEMAS,
      ...PROXY_HOST_PREVIEW_OPENAPI_SCHEMAS,
      ...HIGH_AVAILABILITY_OPENAPI_SCHEMAS,
      ...SHARED_STATE_OPENAPI_SCHEMAS,
      ...IDENTITY_OPENAPI_SCHEMAS,
      ...IDENTITY_OVERVIEW_OPENAPI_SCHEMAS,
      ...GOVERNANCE_OPENAPI_SCHEMAS,
      Error: {
        type: "object",
        properties: { error: { type: "string" } },
        required: ["error"],
      },
      Token: {
        type: "object",
        properties: {
          id: { type: "integer" },
          name: { type: "string" },
          createdBy: { type: "integer" },
          createdAt: { type: "string", format: "date-time" },
          lastUsedAt: { type: ["string", "null"], format: "date-time" },
          expiresAt: { type: ["string", "null"], format: "date-time" },
          scopes: {
            type: ["array", "null"],
            items: { type: "string", enum: [...PERMISSIONS] },
            description:
              "The permissions the token is limited to, as given at creation; null: the same access as its owner's role. " +
              "On every request the token holds its owner's current permissions intersected with these (a write scope also " +
              "grants the area's read). A token with scopes is never an administrator and cannot use the endpoints for its " +
              "owner's account (sessions, tokens, passkeys, preferences, MFA state, access review assignments).",
          },
        },
        required: ["id", "name", "createdBy", "createdAt", "scopes"],
      },
      TokenInput: {
        type: "object",
        description: "Note: this endpoint accepts expires_at (snake_case) for input; the rest of the API uses camelCase.",
        properties: {
          name: { type: "string", example: "Terraform" },
          expires_at: { type: "string", format: "date-time", description: "Optional expiration date (ISO 8601). Field name is snake_case for this endpoint." },
          expiresIn: {
            type: "string",
            enum: ["30d", "90d", "365d", "never"],
            description: "Instead of expires_at: expire 30, 90 or 365 days from now, or never. Giving both is refused.",
          },
          scopes: {
            type: ["array", "null"],
            items: { type: "string", enum: [...PERMISSIONS] },
            minItems: 1,
            description:
              "Limit the token to these permissions; each must be one your role holds now (400 otherwise). " +
              "Leave out or null for the same access as your role.",
            example: ["proxy_hosts:write", "certificates:read"],
          },
        },
        required: ["name"],
      },

      // ── Shared sub-schemas ──────────────────────────────────────
      AuthentikConfig: {
        type: "object",
        description: "Authentik SSO forward-auth configuration",
        properties: {
          enabled: { type: "boolean" },
          outpostDomain: { type: ["string", "null"], example: "auth.example.com" },
          outpostUpstream: { type: ["string", "null"], example: "http://authentik:9000" },
          authEndpoint: { type: ["string", "null"] },
          copyHeaders: { type: "array", items: { type: "string" }, description: "Headers to copy from Authentik response" },
          trustedProxies: { type: "array", items: { type: "string" }, example: ["private_ranges"] },
          setOutpostHostHeader: { type: "boolean" },
          protectedPaths: { type: ["array", "null"], items: { type: "string" }, description: "Paths to protect (null = all)" },
          excludedPaths: { type: ["array", "null"], items: { type: "string" }, description: "Paths to exclude from auth (bypassed while rest is protected)" },
          bypassSources: { type: ["array", "null"], items: { type: "string" }, description: "IP addresses, CIDR ranges or private_ranges whose requests skip sign-in and reach the upstream directly. Everything else on the host (WAF, rate limits, access list, path blocks) still applies. Matched against the client address Caddy works out, so Trusted proxies applies; at most 100 entries, and a range that matches every address is refused." },
        },
      },
      LoadBalancerConfig: {
        type: "object",
        description: "Load balancing configuration for multiple upstreams",
        properties: {
          enabled: { type: "boolean" },
          policy: { type: "string", enum: ["random", "round_robin", "least_conn", "ip_hash", "first", "header", "cookie", "uri_hash"] },
          policyHeaderField: { type: ["string", "null"], description: "Header name for 'header' policy" },
          policyCookieName: { type: ["string", "null"], description: "Cookie name for 'cookie' policy" },
          policyCookieSecret: { type: ["string", "null"] },
          tryDuration: { type: ["string", "null"], example: "5s" },
          tryInterval: { type: ["string", "null"], example: "250ms" },
          retries: { type: ["integer", "null"] },
          activeHealthCheck: {
            type: ["object", "null"],
            properties: {
              enabled: { type: "boolean" },
              uri: { type: ["string", "null"], example: "/health" },
              port: { type: ["integer", "null"] },
              interval: { type: ["string", "null"], example: "30s" },
              timeout: { type: ["string", "null"], example: "5s" },
              status: { type: ["integer", "null"], example: 200 },
              body: { type: ["string", "null"] },
            },
          },
          passiveHealthCheck: {
            type: ["object", "null"],
            properties: {
              enabled: { type: "boolean" },
              failDuration: { type: ["string", "null"], example: "30s" },
              maxFails: { type: ["integer", "null"], example: 3 },
              unhealthyStatus: { type: ["array", "null"], items: { type: "integer" } },
              unhealthyLatency: { type: ["string", "null"], example: "5s" },
            },
          },
        },
      },
      L4LoadBalancerConfig: {
        type: "object",
        description: "L4 load balancing configuration",
        properties: {
          enabled: { type: "boolean" },
          policy: { type: "string", enum: ["random", "round_robin", "least_conn", "ip_hash", "first"] },
          tryDuration: { type: ["string", "null"] },
          tryInterval: { type: ["string", "null"] },
          activeHealthCheck: {
            type: ["object", "null"],
            properties: {
              enabled: { type: "boolean" },
              port: { type: ["integer", "null"] },
              interval: { type: ["string", "null"] },
              timeout: { type: ["string", "null"] },
            },
          },
          passiveHealthCheck: {
            type: ["object", "null"],
            properties: {
              enabled: { type: "boolean" },
              failDuration: { type: ["string", "null"] },
              maxFails: { type: ["integer", "null"] },
            },
          },
        },
      },
      DnsResolverConfig: {
        type: "object",
        description: "Custom DNS resolver for upstream resolution",
        properties: {
          enabled: { type: "boolean" },
          resolvers: { type: "array", items: { type: "string" }, example: ["1.1.1.1", "8.8.8.8"] },
          fallbacks: { type: ["array", "null"], items: { type: "string" } },
          timeout: { type: ["string", "null"], example: "5s" },
        },
      },
      UpstreamDnsResolutionConfig: {
        type: "object",
        description: "Upstream DNS address family preference",
        properties: {
          enabled: { type: ["boolean", "null"] },
          family: { type: ["string", "null"], enum: ["ipv4", "ipv6", "both", null] },
        },
      },
      GeoBlockConfig: {
        type: "object",
        description: "Geographic/network-based access control",
        properties: {
          enabled: { type: "boolean" },
          block_countries: { type: "array", items: { type: "string" }, example: ["CN", "RU"], description: "ISO 3166-1 alpha-2 codes" },
          block_continents: { type: "array", items: { type: "string" }, example: ["AS"], description: "AF, AN, AS, EU, NA, OC, SA" },
          block_asns: { type: "array", items: { type: "integer" } },
          block_cidrs: { type: "array", items: { type: "string" }, example: ["10.0.0.0/8"] },
          block_ips: { type: "array", items: { type: "string" } },
          allow_countries: { type: "array", items: { type: "string" } },
          allow_continents: { type: "array", items: { type: "string" } },
          allow_asns: { type: "array", items: { type: "integer" } },
          allow_cidrs: { type: "array", items: { type: "string" } },
          allow_ips: { type: "array", items: { type: "string" } },
          trusted_proxies: { type: "array", items: { type: "string" }, description: "Trusted proxy CIDRs for X-Forwarded-For" },
          fail_closed: { type: "boolean", description: "Block when client IP cannot be determined" },
          response_status: { type: "integer", example: 403 },
          response_body: { type: "string", example: "Forbidden" },
          response_headers: { type: "object", additionalProperties: { type: "string" }, example: { "Content-Type": "text/plain", "X-Custom": "blocked" }, description: "Custom response headers (header name → value)" },
          redirect_url: { type: "string", description: "If set, 302 redirect instead of status/body" },
        },
      },
      WafConfig: {
        type: "object",
        description:
          "Web Application Firewall configuration of the host. Its WAF mode: enabled false is off; otherwise mode On blocks, " +
          "DetectionOnly logs without blocking, Off is off, and no mode inherits the global mode (see PUT /api/v1/waf/hosts/{id}).",
        properties: {
          enabled: { type: "boolean" },
          mode: { type: "string", enum: ["Off", "On", "DetectionOnly"], description: "Leave out to inherit the global mode" },
          load_owasp_crs: { type: "boolean", description: "Load OWASP Core Rule Set" },
          custom_directives: { type: "string", description: "Custom WAF directives" },
          excluded_rule_ids: {
            type: "array",
            items: { type: "integer", minimum: 1, maximum: 2147483647 },
            description:
              "Rules excluded for this host on every path and variable: the host's whole-host exclusions (/api/v1/waf/exclusions). " +
              "Sending a list replaces those (exclusions with a path or variable stay); leaving it out keeps them.",
          },
          waf_mode: { type: "string", enum: ["merge", "override"], description: "How per-host WAF merges with global" },
          request_body_limit: { type: "integer", minimum: 1024, maximum: 1073741824, description: "SecRequestBodyLimit in bytes. Coraza rejects values above 1 GiB. Unset inherits Coraza's default (12.5 MiB when the OWASP CRS is loaded, else 128 MiB)" },
          request_body_in_memory_limit: { type: "integer", minimum: 1024, maximum: 1073741824, description: "SecRequestBodyInMemoryLimit in bytes; must not exceed request_body_limit" },
          request_body_limit_action: { type: "string", enum: ["Reject", "ProcessPartial"], description: "SecRequestBodyLimitAction — reject oversized bodies or inspect the buffered part and forward the rest" },
        },
      },
      RateLimitRule: {
        type: "object",
        description:
          "One rate limit: requests matching the path and methods are counted per key, and over `events` per `window` the client gets 429 Too Many Requests with Retry-After.",
        properties: {
          path: {
            type: "string",
            default: "*",
            maxLength: 256,
            example: "/login",
            description: "Caddy path pattern (`*` wildcards, %XX escapes, no braces); `*` matches every path. Matched as the client sent it, before rewrites.",
          },
          methods: {
            type: "array",
            items: { type: "string", enum: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"] },
            default: [],
            description: "Methods counted; empty counts every method",
          },
          key: {
            type: "string",
            enum: ["client_ip", "header", "forward_auth_user"],
            default: "client_ip",
            description:
              "client_ip: the client IP after trusted proxies (IPv6 grouped by ipv6Prefix). header: the value of `header`; requests without it count per client IP. forward_auth_user: the user signed in through the built-in forward auth; other requests, and hosts without it, count per client IP.",
          },
          header: { type: "string", maxLength: 128, example: "X-Api-Key", description: "Header name (RFC 7230 token); required with key `header`, refused otherwise" },
          events: { type: "integer", minimum: 1, maximum: 1000, example: 10, description: "Requests allowed per window" },
          window: {
            type: "string",
            pattern: "^[1-9][0-9]{0,3}(s|m|h)$",
            example: "1m",
            description: "Sliding window: whole seconds, minutes or hours, from 1s to 1h",
          },
        },
        required: ["events", "window"],
      },
      ProxyHostRateLimit: {
        type: "object",
        description:
          "Per-host rate limiting. Disabled or absent: the host inherits the global defaults (settings group rate-limit). merge: the defaults and these rules apply. override: only these rules; with none, nothing is limited.",
        properties: {
          enabled: { type: "boolean", default: true },
          mode: { type: "string", enum: ["merge", "override"], default: "merge" },
          rules: { type: "array", maxItems: 20, items: { $ref: "#/components/schemas/RateLimitRule" } },
        },
      },
      RateLimitSettings: {
        type: "object",
        description: "Global rate limiting defaults (settings group rate-limit)",
        properties: {
          enabled: { type: "boolean", description: "Whether the default rules apply to hosts that inherit or merge them" },
          rules: { type: "array", maxItems: 20, items: { $ref: "#/components/schemas/RateLimitRule" } },
          allowlist: {
            type: "array",
            maxItems: 256,
            items: { type: "string" },
            example: ["192.0.2.10", "198.51.100.0/24"],
            description: "Client IPs and CIDR ranges (or private_ranges) that no rule limits, the defaults or a host's own",
          },
          ipv6Prefix: {
            type: "integer",
            minimum: 32,
            maximum: 128,
            default: 64,
            description: "Prefix length IPv6 clients are grouped by for client-IP keys; 128 counts each address",
          },
        },
        required: ["enabled"],
      },
      MtlsConfig: {
        type: "object",
        description: "Mutual TLS (client certificate) configuration",
        properties: {
          enabled: { type: "boolean" },
          ca_certificate_ids: { type: "array", items: { type: "integer" }, description: "CA certificate IDs to trust" },
        },
      },
      ForwardAuthConfig: {
        type: "object",
        description: "Generic forward auth through an external auth server (Authelia preset or custom)",
        properties: {
          enabled: { type: "boolean" },
          provider: { type: "string", enum: ["authelia", "custom"] },
          authUpstream: { type: ["string", "null"], description: "Base URL of the auth server, e.g. http://authelia:9091" },
          authEndpoint: { type: ["string", "null"], description: "URI the auth subrequest is rewritten to; may include a query string" },
          copyHeaders: { type: "array", items: { type: "string" }, description: "Headers copied from the auth server's 2xx response to the upstream request" },
          trustedProxies: { type: "array", items: { type: "string" } },
          apiSplit: { type: "boolean", description: "Non-browser requests get a 401 instead of the auth server's login redirect" },
          apiBypassHeaders: { type: "array", items: { type: "string" }, description: "Requests carrying any of these headers skip forward auth" },
          protectedPaths: { type: ["array", "null"], items: { type: "string" }, description: "Paths to protect (null = all)" },
          excludedPaths: { type: ["array", "null"], items: { type: "string" }, description: "Paths to exclude from auth" },
          bypassSources: { type: ["array", "null"], items: { type: "string" }, description: "IP addresses, CIDR ranges or private_ranges whose requests skip sign-in and reach the upstream directly. Everything else on the host (WAF, rate limits, access list, path blocks) still applies. Matched against the client address Caddy works out, so Trusted proxies applies; at most 100 entries, and a range that matches every address is refused." },
        },
      },
      IngressiForwardAuthConfig: {
        type: "object",
        description: `Built-in ${BRAND_NAME} forward-auth (replaces Authentik when enabled)`,
        properties: {
          enabled: { type: "boolean" },
          protected_paths: { type: ["array", "null"], items: { type: "string" }, description: "Paths to protect (null = all)" },
          excluded_paths: { type: ["array", "null"], items: { type: "string" }, description: "Paths to exclude from auth" },
          bypass_sources: { type: ["array", "null"], items: { type: "string" }, description: "IP addresses, CIDR ranges or private_ranges whose requests skip sign-in and reach the upstream directly. Everything else on the host (WAF, rate limits, access list, path blocks) still applies. Matched against the client address Caddy works out, so Trusted proxies applies; at most 100 entries, and a range that matches every address is refused." },
        },
      },
      RedirectRule: {
        type: "object",
        description: "HTTP redirect rule",
        properties: {
          from: { type: "string", example: "/.well-known/carddav", description: "Path pattern to match" },
          to: { type: "string", example: "/remote.php/dav/", description: "Redirect destination" },
          status: { type: "integer", enum: [301, 302, 307, 308], example: 301 },
        },
        required: ["from", "to", "status"],
      },
      RewriteConfig: {
        type: "object",
        description: "Path rewrite (strip prefix)",
        properties: {
          path_prefix: { type: "string", example: "/app", description: "Prefix to strip from request path" },
        },
        required: ["path_prefix"],
      },
      LocationRule: {
        type: "object",
        description: "Route a path pattern to specific upstream servers (like nginx location blocks)",
        properties: {
          path: { type: "string", example: "/ws/*", description: "Caddy path pattern to match" },
          upstreams: { type: "array", items: { type: "string" }, example: ["ws-backend:8080", "ws-backend2:8080"], description: "Upstream servers for this path" },
          loadBalancer: { oneOf: [{ $ref: "#/components/schemas/LoadBalancerConfig" }, { type: "null" }], description: "Optional per-rule load balancing and health checks for this path's upstreams" },
        },
        required: ["path", "upstreams"],
      },
      PathAllowRule: {
        type: "object",
        description: "Allow a request path to bypass any matching Path Block and reach the upstream. Evaluated before blocks.",
        properties: {
          path: { type: "string", example: "/secret", description: "Caddy path pattern to allow through" },
        },
        required: ["path"],
      },
      PathBlockRule: {
        type: "object",
        description: "Block a request path with a static response (no proxying)",
        properties: {
          path: { type: "string", example: "/dns-query", description: "Caddy path pattern to match" },
          status: { type: "integer", enum: [400, 401, 403, 404, 410, 418, 451, 500, 502, 503], example: 403 },
          body: { type: "string", example: "Forbidden", description: "Optional response body" },
        },
        required: ["path", "status"],
      },
      PathRewriteRule: {
        type: "object",
        description: "Internally rewrite the request URI before proxying (client URL is unchanged)",
        properties: {
          from: { type: "string", example: "/secretpath", description: "Caddy path pattern to match" },
          to: { type: "string", example: "/dns-query", description: "Internal target URI" },
        },
        required: ["from", "to"],
      },

      // ── Main resource schemas ───────────────────────────────────
      ProxyHost: {
        type: "object",
        properties: {
          id: { type: "integer" },
          name: { type: "string" },
          domains: { type: "array", items: { type: "string" }, example: ["example.com", "www.example.com"] },
          upstreams: { type: "array", items: { type: "string" }, example: ["localhost:8080"] },
          certificateId: { type: ["integer", "null"] },
          accessListId: { type: ["integer", "null"] },
          sslForced: { type: "boolean" },
          hstsEnabled: { type: "boolean" },
          hstsSubdomains: { type: "boolean" },
          allowWebsocket: { type: "boolean" },
          preserveHostHeader: { type: "boolean" },
          skipHttpsHostnameValidation: { type: "boolean" },
          enabled: { type: "boolean" },
          createdAt: { type: "string", format: "date-time" },
          updatedAt: { type: "string", format: "date-time" },
          customReverseProxyJson: { type: ["string", "null"], description: "Raw Caddy JSON for reverse_proxy handler" },
          customPreHandlersJson: { type: ["string", "null"], description: "Raw Caddy JSON for handlers before reverse_proxy" },
          authentik: { oneOf: [{ $ref: "#/components/schemas/AuthentikConfig" }, { type: "null" }] },
          loadBalancer: { oneOf: [{ $ref: "#/components/schemas/LoadBalancerConfig" }, { type: "null" }] },
          dnsResolver: { oneOf: [{ $ref: "#/components/schemas/DnsResolverConfig" }, { type: "null" }] },
          upstreamDnsResolution: { oneOf: [{ $ref: "#/components/schemas/UpstreamDnsResolutionConfig" }, { type: "null" }] },
          geoblock: { oneOf: [{ $ref: "#/components/schemas/GeoBlockConfig" }, { type: "null" }] },
          geoblockMode: { type: "string", enum: ["merge", "override"], description: "How per-host geoblock merges with global" },
          waf: { oneOf: [{ $ref: "#/components/schemas/WafConfig" }, { type: "null" }] },
          mtls: { oneOf: [{ $ref: "#/components/schemas/MtlsConfig" }, { type: "null" }] },
          ingressiForwardAuth: { oneOf: [{ $ref: "#/components/schemas/IngressiForwardAuthConfig" }, { type: "null" }] },
          cpmForwardAuth: {
            oneOf: [{ $ref: "#/components/schemas/IngressiForwardAuthConfig" }, { type: "null" }],
            deprecated: true,
            description: "Former name of ingressiForwardAuth, with the same value. Accepted on input when ingressiForwardAuth is absent.",
          },
          forwardAuth: { oneOf: [{ $ref: "#/components/schemas/ForwardAuthConfig" }, { type: "null" }] },
          redirects: { type: "array", items: { $ref: "#/components/schemas/RedirectRule" } },
          rewrite: { oneOf: [{ $ref: "#/components/schemas/RewriteConfig" }, { type: "null" }] },
          locationRules: { type: "array", items: { $ref: "#/components/schemas/LocationRule" }, description: "Path-based routing rules (routes specific paths to different upstreams)" },
          pathAllows: { type: "array", items: { $ref: "#/components/schemas/PathAllowRule" }, description: "Paths that bypass any matching Path Block and reach the upstream (evaluated first)" },
          pathBlocks: { type: "array", items: { $ref: "#/components/schemas/PathBlockRule" }, description: "Paths blocked with a static response" },
          pathRewrites: { type: "array", items: { $ref: "#/components/schemas/PathRewriteRule" }, description: "Internal URI rewrites applied before proxying" },
          rateLimit: { oneOf: [{ $ref: "#/components/schemas/ProxyHostRateLimit" }, { type: "null" }], description: "Per-host rate limiting; null inherits the global defaults" },
          tags: { $ref: "#/components/schemas/HostTags" },
        },
        required: ["id", "name", "domains", "upstreams", "enabled", "createdAt", "updatedAt"],
      },
      ProxyHostInput: {
        type: "object",
        properties: {
          name: { type: "string", example: "My App" },
          domains: { type: "array", items: { type: "string" }, example: ["app.example.com"] },
          upstreams: { type: "array", items: { type: "string" }, example: ["localhost:3000"] },
          certificateId: { type: ["integer", "null"] },
          accessListId: { type: ["integer", "null"] },
          sslForced: { type: "boolean" },
          hstsEnabled: { type: "boolean" },
          hstsSubdomains: { type: "boolean" },
          allowWebsocket: { type: "boolean" },
          preserveHostHeader: { type: "boolean" },
          skipHttpsHostnameValidation: { type: "boolean" },
          enabled: { type: "boolean" },
          customReverseProxyJson: { type: ["string", "null"] },
          customPreHandlersJson: { type: ["string", "null"] },
          authentik: { oneOf: [{ $ref: "#/components/schemas/AuthentikConfig" }, { type: "null" }] },
          loadBalancer: { oneOf: [{ $ref: "#/components/schemas/LoadBalancerConfig" }, { type: "null" }] },
          dnsResolver: { oneOf: [{ $ref: "#/components/schemas/DnsResolverConfig" }, { type: "null" }] },
          upstreamDnsResolution: { oneOf: [{ $ref: "#/components/schemas/UpstreamDnsResolutionConfig" }, { type: "null" }] },
          geoblock: { oneOf: [{ $ref: "#/components/schemas/GeoBlockConfig" }, { type: "null" }] },
          geoblockMode: { type: "string", enum: ["merge", "override"] },
          waf: { oneOf: [{ $ref: "#/components/schemas/WafConfig" }, { type: "null" }] },
          mtls: { oneOf: [{ $ref: "#/components/schemas/MtlsConfig" }, { type: "null" }] },
          ingressiForwardAuth: { oneOf: [{ $ref: "#/components/schemas/IngressiForwardAuthConfig" }, { type: "null" }] },
          cpmForwardAuth: {
            oneOf: [{ $ref: "#/components/schemas/IngressiForwardAuthConfig" }, { type: "null" }],
            deprecated: true,
            description: "Former name of ingressiForwardAuth, with the same value. Accepted on input when ingressiForwardAuth is absent.",
          },
          forwardAuth: { oneOf: [{ $ref: "#/components/schemas/ForwardAuthConfig" }, { type: "null" }] },
          redirects: { type: "array", items: { $ref: "#/components/schemas/RedirectRule" } },
          rewrite: { oneOf: [{ $ref: "#/components/schemas/RewriteConfig" }, { type: "null" }] },
          locationRules: { type: "array", items: { $ref: "#/components/schemas/LocationRule" }, description: "Path-based routing rules (routes specific paths to different upstreams)" },
          pathAllows: { type: "array", items: { $ref: "#/components/schemas/PathAllowRule" }, description: "Paths that bypass any matching Path Block and reach the upstream (evaluated first)" },
          pathBlocks: { type: "array", items: { $ref: "#/components/schemas/PathBlockRule" }, description: "Paths blocked with a static response" },
          pathRewrites: { type: "array", items: { $ref: "#/components/schemas/PathRewriteRule" }, description: "Internal URI rewrites applied before proxying" },
          rateLimit: {
            oneOf: [{ $ref: "#/components/schemas/ProxyHostRateLimit" }, { type: "null" }],
            description: "Per-host rate limiting; replaces the stored value, null removes it. Validated strictly (400 on an unknown field or a value out of range)",
          },
          tags: { $ref: "#/components/schemas/HostTagsInput" },
        },
        required: ["name", "domains", "upstreams"],
      },
      L4ProxyHost: {
        type: "object",
        properties: {
          id: { type: "integer" },
          name: { type: "string" },
          protocol: { type: "string", enum: ["tcp", "udp"] },
          listenAddress: { type: "string", example: ":5432", description: "Single host:port or :port to listen on. Ports 80, 443 and 2019 are reserved for Caddy's own listeners and are rejected." },
          upstreams: { type: "array", items: { type: "string" }, example: ["db-server:5432"] },
          matcherType: { type: "string", enum: ["none", "tls_sni", "http_host", "proxy_protocol"] },
          matcherValue: { type: "array", items: { type: "string" }, description: "Match values for tls_sni / http_host (empty otherwise)" },
          tlsTermination: { type: "boolean" },
          proxyProtocolVersion: { type: ["string", "null"], enum: ["v1", "v2", null] },
          proxyProtocolReceive: { type: "boolean", description: "Trust inbound PROXY protocol header from upstream LBs" },
          enabled: { type: "boolean" },
          loadBalancer: { oneOf: [{ $ref: "#/components/schemas/L4LoadBalancerConfig" }, { type: "null" }] },
          dnsResolver: { oneOf: [{ $ref: "#/components/schemas/DnsResolverConfig" }, { type: "null" }] },
          upstreamDnsResolution: { oneOf: [{ $ref: "#/components/schemas/UpstreamDnsResolutionConfig" }, { type: "null" }] },
          geoblock: { oneOf: [{ $ref: "#/components/schemas/GeoBlockConfig" }, { type: "null" }] },
          geoblockMode: { type: "string", enum: ["merge", "override"] },
          tags: { $ref: "#/components/schemas/HostTags" },
          createdAt: { type: "string", format: "date-time" },
          updatedAt: { type: "string", format: "date-time" },
        },
        required: ["id", "name", "listenAddress", "upstreams", "protocol", "enabled", "createdAt", "updatedAt"],
      },
      L4ProxyHostInput: {
        type: "object",
        properties: {
          name: { type: "string", example: "PostgreSQL Proxy" },
          protocol: { type: "string", enum: ["tcp", "udp"] },
          listenAddress: { type: "string", example: ":5432", description: "Single host:port or :port. Ports 80, 443 and 2019 are reserved and rejected." },
          upstreams: { type: "array", items: { type: "string" }, example: ["db:5432"] },
          matcherType: { type: "string", enum: ["none", "tls_sni", "http_host", "proxy_protocol"] },
          matcherValue: { type: "array", items: { type: "string" } },
          tlsTermination: { type: "boolean" },
          proxyProtocolVersion: { type: ["string", "null"], enum: ["v1", "v2", null] },
          proxyProtocolReceive: { type: "boolean" },
          enabled: { type: "boolean" },
          loadBalancer: { oneOf: [{ $ref: "#/components/schemas/L4LoadBalancerConfig" }, { type: "null" }] },
          dnsResolver: { oneOf: [{ $ref: "#/components/schemas/DnsResolverConfig" }, { type: "null" }] },
          upstreamDnsResolution: { oneOf: [{ $ref: "#/components/schemas/UpstreamDnsResolutionConfig" }, { type: "null" }] },
          geoblock: { oneOf: [{ $ref: "#/components/schemas/GeoBlockConfig" }, { type: "null" }] },
          geoblockMode: { type: "string", enum: ["merge", "override"] },
          tags: { $ref: "#/components/schemas/HostTagsInput" },
        },
        required: ["name", "listenAddress", "upstreams", "protocol"],
      },
      HostTags: {
        type: "array",
        description:
          "Free-form labels. Tags alone change nothing; a custom role can be limited to hosts carrying one of its tags.",
        items: { type: "string", maxLength: MAX_TAG_LENGTH, pattern: "^[a-z0-9][a-z0-9._:/-]*$" },
        maxItems: MAX_TAGS_PER_HOST,
        example: ["team-a", "production"],
      },
      HostTagsInput: {
        type: ["array", "null"],
        description:
          "Tags are trimmed, lowercased, deduplicated and sorted; each starts with a letter or digit and contains only letters, " +
          `digits and . _ : / - (at most ${MAX_TAG_LENGTH} characters, at most ${MAX_TAGS_PER_HOST} tags; 400 otherwise). ` +
          "Omit to keep the host's tags; null or [] clears them. With a custom role limited to tagged hosts, only the role's " +
          "own tags can be added or removed (403 for others), tags outside the scope already on the host are kept, and at " +
          "least one of the role's tags must remain (400).",
        items: { type: "string", maxLength: MAX_TAG_LENGTH },
        maxItems: MAX_TAGS_PER_HOST,
        example: ["team-a"],
      },
      Certificate: {
        type: "object",
        properties: {
          id: { type: "integer" },
          name: { type: "string" },
          type: { type: "string", enum: ["managed", "imported"] },
          domainNames: { type: "array", items: { type: "string" }, example: ["example.com", "*.example.com"] },
          autoRenew: { type: "boolean" },
          providerOptions: {
            type: ["object", "null"],
            description: "Optional reference to a centrally configured DNS provider. Credential values are never returned here.",
            properties: { provider: { type: "string" } },
            required: ["provider"],
            additionalProperties: false,
          },
          certificatePem: { type: ["string", "null"], description: "PEM-encoded certificate (imported type only)" },
          hasPrivateKey: { type: "boolean", description: "Whether write-only private key material is stored" },
          createdAt: { type: "string", format: "date-time" },
          updatedAt: { type: "string", format: "date-time" },
        },
        required: ["id", "name", "type", "domainNames", "hasPrivateKey", "createdAt", "updatedAt"],
      },
      CertificateInput: {
        type: "object",
        properties: {
          name: { type: "string", example: "Wildcard Cert" },
          type: { type: "string", enum: ["managed", "imported"] },
          domainNames: { type: "array", items: { type: "string" } },
          autoRenew: { type: "boolean" },
          providerOptions: {
            type: ["object", "null"],
            description: "DNS provider for this managed certificate, by the name it has under Certificate settings. Without it the default provider is used; null on update clears it.",
            properties: { provider: { type: "string" } },
            required: ["provider"],
            additionalProperties: false,
          },
          certificatePem: { type: ["string", "null"] },
          privateKeyPem: { type: ["string", "null"], writeOnly: true },
        },
        required: ["name", "type", "domainNames"],
      },
      CaCertificate: {
        type: "object",
        properties: {
          id: { type: "integer" },
          name: { type: "string" },
          certificatePem: { type: "string", description: "PEM-encoded CA certificate" },
          hasPrivateKey: { type: "boolean", description: "Whether a private key is stored (for issuing client certs)" },
          createdAt: { type: "string", format: "date-time" },
          updatedAt: { type: "string", format: "date-time" },
        },
        required: ["id", "name", "certificatePem", "hasPrivateKey", "createdAt", "updatedAt"],
      },
      CaCertificateInput: {
        type: "object",
        properties: {
          name: { type: "string", example: "Internal CA" },
          certificatePem: { type: "string", description: "PEM-encoded CA certificate" },
          privateKeyPem: { type: "string", description: "PEM-encoded private key (optional, needed for issuing client certs)" },
        },
        required: ["name", "certificatePem"],
      },
      ClientCertificate: {
        type: "object",
        properties: {
          id: { type: "integer" },
          caCertificateId: { type: "integer" },
          commonName: { type: "string", example: "client-device-01" },
          serialNumber: { type: "string" },
          fingerprintSha256: { type: "string" },
          certificatePem: { type: "string" },
          validFrom: { type: "string", format: "date-time" },
          validTo: { type: "string", format: "date-time" },
          revokedAt: { type: ["string", "null"], format: "date-time" },
          createdAt: { type: "string", format: "date-time" },
          updatedAt: { type: "string", format: "date-time" },
        },
        required: ["id", "caCertificateId", "commonName", "serialNumber", "fingerprintSha256", "certificatePem", "validFrom", "validTo", "createdAt", "updatedAt"],
      },
      ClientCertificateInput: {
        type: "object",
        description: "Store a pre-issued client certificate. All PEM/serial/fingerprint/validity fields must be provided.",
        properties: {
          caCertificateId: { type: "integer", description: "ID of the CA certificate this cert was issued from" },
          commonName: { type: "string", example: "client-device-01" },
          serialNumber: { type: "string" },
          fingerprintSha256: { type: "string" },
          certificatePem: { type: "string" },
          validFrom: { type: "string", format: "date-time" },
          validTo: { type: "string", format: "date-time" },
        },
        required: ["caCertificateId", "commonName", "serialNumber", "fingerprintSha256", "certificatePem", "validFrom", "validTo"],
      },

      // ── Settings schemas ────────────────────────────────────────
      GeneralSettings: {
        type: "object",
        properties: {
          primaryDomain: { type: "string", example: "example.com" },
          acmeEmail: { type: "string", format: "email", example: "admin@example.com" },
        },
        required: ["primaryDomain"],
      },
      CloudflareSettings: {
        type: "object",
        description: "Write-only legacy Cloudflare settings. The API token is accepted on update but never returned by GET.",
        properties: {
          apiToken: { type: "string", description: "Cloudflare API token", writeOnly: true },
          zoneId: { type: "string" },
          accountId: { type: "string" },
        },
        required: ["apiToken"],
      },
      CloudflareStatus: {
        type: "object",
        description: "Non-secret metadata for the legacy Cloudflare settings group.",
        properties: {
          hasApiToken: { type: "boolean" },
          zoneId: { type: "string" },
          accountId: { type: "string" },
        },
        required: ["hasApiToken"],
      },
      DnsProviderSettings: {
        type: "object",
        description: "Write-only DNS provider configuration for ACME DNS-01 challenges. Credential values are accepted on update but never returned by GET.",
        properties: {
          providers: {
            type: "object",
            additionalProperties: {
              type: "object",
              additionalProperties: { type: "string", writeOnly: true },
              description: "Credential key-value pairs for this provider",
            },
            description: "Configured providers keyed by name (e.g. { cloudflare: { api_token: '...' }, route53: { ... } })",
          },
          default: {
            type: "string",
            nullable: true,
            description: "Name of the default provider used for DNS-01 challenges (null = HTTP-01 only)",
          },
        },
        required: ["providers", "default"],
      },
      DnsProviderStatus: {
        type: "object",
        description: "Non-secret metadata for configured DNS providers. Credential values are write-only.",
        properties: {
          providers: {
            type: "object",
            additionalProperties: {
              type: "object",
              properties: {
                configuredFields: {
                  type: "array",
                  items: { type: "string" },
                  description: "Credential field names which have a stored, non-empty value",
                },
              },
              required: ["configuredFields"],
            },
            description: "Configured providers keyed by provider name; values contain metadata only",
          },
          default: {
            type: ["string", "null"],
            description: "Name of the default provider used for DNS-01 challenges",
          },
        },
        required: ["providers", "default"],
      },
      AuthentikSettings: {
        type: "object",
        properties: {
          outpostDomain: { type: "string", example: "auth.example.com" },
          outpostUpstream: { type: "string", example: "http://authentik:9000" },
          authEndpoint: { type: "string" },
        },
        required: ["outpostDomain", "outpostUpstream"],
      },
      MetricsSettings: {
        type: "object",
        properties: {
          enabled: { type: "boolean" },
          port: { type: "integer", example: 9090, description: "Prometheus metrics port" },
        },
        required: ["enabled"],
      },
      LoggingSettings: {
        type: "object",
        properties: {
          enabled: { type: "boolean" },
          format: { type: "string", enum: ["json", "console"] },
        },
        required: ["enabled"],
      },
      DefaultResponseSettings: {
        type: "object",
        description: "Catch-all behavior for requests that do not match a configured proxy host.",
        properties: {
          mode: {
            type: "string",
            enum: ["caddy", "respond", "redirect", "abort"],
            description: "caddy preserves native routing/automatic-HTTPS behavior; abort closes the connection without a response.",
          },
          status: {
            type: "integer",
            minimum: 200,
            maximum: 599,
            description: "HTTP response status, or one of 301/302/303/307/308 for redirect mode.",
          },
          body: { type: "string", description: "Body used by respond mode." },
          headers: {
            type: "object",
            additionalProperties: { type: "string" },
            description: "Optional response headers. Values must not contain newlines.",
          },
          redirectUrl: { type: "string", description: "Target used by redirect mode." },
        },
        required: ["mode"],
      },
      ResponseHeadersSettings: {
        type: "object",
        description:
          "Response headers set or removed on every response of every host (Host defaults → Response headers). Applied after the upstream's, Caddy's and the host's own headers.",
        properties: {
          set: {
            type: "object",
            additionalProperties: { type: "string" },
            example: { Server: "web" },
            description: "Headers set on every response, replacing any value already there. Request placeholders such as {http.request.host} are filled in; request header and cookie placeholders are refused.",
          },
          remove: {
            type: "array",
            items: { type: "string" },
            example: ["Via"],
            description: "Headers removed from every response. A name cannot be both set and removed.",
          },
        },
      },
      TrustedProxiesSettings: {
        type: "object",
        description: "How Caddy works out the client address behind load balancers and CDNs (Host defaults → Trusted proxies).",
        properties: {
          ranges: {
            type: "array",
            items: { type: "string" },
            example: ["private_ranges", "172.21.0.1/32"],
            description: "Proxies whose client address headers are trusted: IPs, CIDR ranges or private_ranges. Empty turns it off.",
          },
          client_ip_headers: {
            type: "array",
            items: { type: "string" },
            example: ["Cf-Connecting-Ip"],
            description: "Headers holding the client address; empty means X-Forwarded-For.",
          },
          strict: { type: "boolean", description: "Read the client address headers from the right, as the trusted proxy added them." },
          default_geoblock: { type: "boolean", description: "Use `ranges` as geo blocking's trusted proxies unless geo blocking lists its own." },
          proxy_protocol_ranges: {
            type: "array",
            items: { type: "string" },
            maxItems: 100,
            example: ["192.168.1.1", "10.0.10.0/24"],
            description:
              "TCP load balancers allowed to send a PROXY protocol header (v1 or v2) to ports 80 and 443: IPs or CIDR ranges, " +
              "stored as network addresses. From them the header is optional; from any other client a header is ignored. " +
              "private_ranges and ranges matching every address are refused. Empty or absent: no PROXY protocol.",
          },
        },
        required: ["ranges"],
      },
      DnsSettings: {
        type: "object",
        properties: {
          enabled: { type: "boolean" },
          resolvers: { type: "array", items: { type: "string" }, example: ["1.1.1.1", "8.8.8.8"] },
          fallbacks: { type: "array", items: { type: "string" } },
          timeout: { type: "string", example: "5s" },
        },
        required: ["enabled", "resolvers"],
      },
      UpstreamDnsSettings: {
        type: "object",
        properties: {
          enabled: { type: "boolean" },
          family: { type: "string", enum: ["ipv4", "ipv6", "both"] },
        },
        required: ["enabled", "family"],
      },
      WafSettings: {
        type: "object",
        description:
          "Global WAF settings. enabled applies the WAF to every proxy host; without it only hosts that turn their WAF on use it. " +
          "mode is the global mode (Off, DetectionOnly: log only, On: blocking), which hosts that inherit their mode use. " +
          "The tuning fields are left out when they hold the CRS default.",
        properties: {
          enabled: { type: "boolean", description: "Apply the WAF to every proxy host" },
          mode: { type: "string", enum: ["Off", "On", "DetectionOnly"] },
          load_owasp_crs: { type: "boolean" },
          custom_directives: { type: "string" },
          excluded_rule_ids: {
            type: "array",
            items: { type: "integer", minimum: 1, maximum: 2147483647 },
            description:
              "Rules excluded for every host that follows or merges with the global settings, on every path and variable: the global " +
              "whole-scope exclusions (/api/v1/waf/exclusions). Sending a list replaces those; leaving it out keeps them.",
          },
          ...WAF_TUNING_OPENAPI_PROPERTIES,
          request_body_limit: { type: "integer", minimum: 1024, maximum: 1073741824, description: "SecRequestBodyLimit in bytes. Coraza rejects values above 1 GiB. Unset inherits Coraza's default (12.5 MiB when the OWASP CRS is loaded, else 128 MiB)" },
          request_body_in_memory_limit: { type: "integer", minimum: 1024, maximum: 1073741824, description: "SecRequestBodyInMemoryLimit in bytes; must not exceed request_body_limit" },
          request_body_limit_action: { type: "string", enum: ["Reject", "ProcessPartial"], description: "SecRequestBodyLimitAction — reject oversized bodies or inspect the buffered part and forward the rest" },
        },
        required: ["enabled", "mode", "load_owasp_crs", "custom_directives"],
      },

      // ── Groups & Roles ─────────────────────────────────────────
      Group: {
        type: "object",
        properties: {
          id: { type: "integer" },
          name: { type: "string" },
          description: { type: ["string", "null"] },
          members: { type: "array", items: { $ref: "#/components/schemas/GroupMember" } },
          createdAt: { type: "string", format: "date-time" },
          updatedAt: { type: "string", format: "date-time" },
        },
        required: ["id", "name", "members", "createdAt", "updatedAt"],
      },
      GroupMember: {
        type: "object",
        properties: {
          userId: { type: "integer" },
          email: { type: "string" },
          name: { type: ["string", "null"] },
          createdAt: { type: "string", format: "date-time" },
        },
        required: ["userId", "email", "createdAt"],
      },
      MtlsRole: {
        type: "object",
        properties: {
          id: { type: "integer" },
          name: { type: "string" },
          description: { type: ["string", "null"] },
          createdAt: { type: "string", format: "date-time" },
          updatedAt: { type: "string", format: "date-time" },
        },
        required: ["id", "name", "createdAt", "updatedAt"],
      },

      // ── Other resources ─────────────────────────────────────────
      Instance: {
        type: "object",
        properties: {
          id: { type: "integer" },
          name: { type: "string" },
          baseUrl: {
            type: "string",
            example: "https://slave.example.com:3000",
            description: 'For a pull replica its identity ("pull:" and a random id); nothing is sent there',
          },
          syncMode: {
            type: "string",
            enum: ["push", "pull"],
            description: "pull: a fleet pull replica, which fetches its configuration (see /api/v1/fleet/pull-replicas); its base URL and token cannot be changed",
          },
          enabled: { type: "boolean" },
          hasToken: { type: "boolean" },
          lastSyncAt: { type: ["string", "null"], format: "date-time" },
          lastSyncError: { type: ["string", "null"] },
          syncKeyPin: {
            oneOf: [{ $ref: "#/components/schemas/SyncKeyPin" }, { type: "null" }],
            description: "The sync key pinned for the instance's base URL; null until a sync pins one",
          },
          createdAt: { type: "string", format: "date-time" },
          updatedAt: { type: "string", format: "date-time" },
        },
        required: ["id", "name", "baseUrl", "syncMode", "enabled", "hasToken", "syncKeyPin", "createdAt", "updatedAt"],
      },
      SyncKeyPin: {
        type: "object",
        description: "A slave sync key pinned by this master (trust on first use, or set by an admin)",
        properties: {
          keyId: {
            type: "string",
            pattern: "^([0-9a-f]{16})?$",
            example: "3f9a1c0b7d2e4a65",
            description: "The first 16 hex characters of the SHA-256 of the public key; empty for an unreadable pin",
          },
          publicKey: {
            type: "string",
            description: "Raw 32-byte X25519 public key, base64; empty for an unreadable pin",
          },
          pinnedAt: { type: "string", description: "When the key was pinned (ISO 8601); empty or as stored for an unreadable pin" },
          source: {
            type: "string",
            examples: ["first-use", "rotation", "manual", "unreadable"],
            description:
              "first-use: the first key the slave presented; rotation: a new key the slave proved with the previously pinned one; " +
              "manual: set by an admin; unreadable: a stored pin this release cannot read (for example one written by a newer release), " +
              "which matches no key, so syncs to the slave fail until the pin is replaced or reset. Other values, from other releases, are kept as stored.",
          },
        },
        required: ["keyId", "publicKey", "pinnedAt", "source"],
      },
      SyncKeyPinInput: {
        type: "object",
        properties: {
          publicKey: {
            type: "string",
            pattern: "^[A-Za-z0-9+/]{43}=$",
            description: "The slave's sync public key (raw 32-byte X25519, base64), as the slave's Instance sync page and GET /api/v1/instances/sync-key show it",
          },
        },
        required: ["publicKey"],
      },
      SyncKeyPinListing: {
        allOf: [
          { $ref: "#/components/schemas/SyncKeyPin" },
          {
            type: "object",
            properties: {
              url: { type: "string", example: "https://replica.example.com", description: "Normalized slave base URL the pin is kept under" },
              slaves: {
                type: "array",
                description: "Instances and INSTANCE_SLAVES entries that sync to the URL",
                items: {
                  oneOf: [
                    {
                      type: "object",
                      properties: {
                        type: { type: "string", enum: ["instance"] },
                        id: { type: "integer" },
                        name: { type: "string" },
                      },
                      required: ["type", "id", "name"],
                    },
                    {
                      type: "object",
                      properties: {
                        type: { type: "string", enum: ["env"] },
                        name: { type: "string" },
                        syncKeyId: {
                          type: ["string", "null"],
                          description: "The entry's syncKeyId (derived from syncPublicKey when only that is set); when set, sync checks it instead of the stored pin",
                        },
                        syncPublicKey: {
                          type: ["string", "null"],
                          description: "The entry's syncPublicKey; when set, sync compares the full key instead of the stored pin",
                        },
                      },
                      required: ["type", "name", "syncKeyId", "syncPublicKey"],
                    },
                  ],
                },
              },
            },
            required: ["url", "slaves"],
          },
        ],
      },
      InstanceSyncKey: {
        type: "object",
        properties: {
          keyId: { type: "string", pattern: "^[0-9a-f]{16}$", example: "3f9a1c0b7d2e4a65" },
          publicKey: { type: "string", description: "Raw 32-byte X25519 public key, base64" },
        },
        required: ["keyId", "publicKey"],
      },
      InstanceUpdate: {
        type: "object",
        description: "Fields to change; the others are kept",
        properties: {
          name: { type: "string", minLength: 1, example: "Slave 1" },
          baseUrl: { type: "string", example: "https://slave.example.com:3000" },
          apiToken: {
            type: "string",
            minLength: 32,
            maxLength: 512,
            description: "New sync token for the slave instance",
          },
          enabled: { type: "boolean" },
        },
      },
      InstanceInput: {
        type: "object",
        properties: {
          name: { type: "string", example: "Slave 1" },
          baseUrl: { type: "string", example: "https://slave.example.com:3000" },
          apiToken: {
            type: "string",
            minLength: 32,
            maxLength: 512,
            description: "Random sync token for the slave instance (generate with: openssl rand -hex 32)",
          },
          enabled: { type: "boolean" },
        },
        required: ["name", "baseUrl", "apiToken"],
      },
      SyncResult: {
        type: "object",
        properties: {
          total: { type: "integer" },
          success: { type: "integer" },
          failed: { type: "integer" },
          skippedHttp: { type: "integer" },
        },
        required: ["total", "success", "failed", "skippedHttp"],
      },
      OauthProvider: {
        type: "object",
        description:
          "OAuth/OIDC provider. clientId is masked; the clientSecret is never exposed. callbackUrl is the exact redirect URI to register at the identity provider.",
        properties: {
          id: { type: "string", example: "corp-idp" },
          name: { type: "string", example: "Corporate IdP" },
          type: { type: "string", enum: ["oidc", "oauth2"] },
          clientId: { type: "string", readOnly: true, example: "••••a1b2" },
          hasClientSecret: { type: "boolean", readOnly: true },
          issuer: { type: ["string", "null"] },
          authorizationUrl: { type: ["string", "null"] },
          tokenUrl: { type: ["string", "null"] },
          userinfoUrl: { type: ["string", "null"] },
          scopes: { type: "string", example: "openid email profile" },
          autoLink: { type: "boolean" },
          enabled: { type: "boolean" },
          source: { type: "string", enum: ["env", "ui"], readOnly: true },
          callbackUrl: {
            type: "string",
            readOnly: true,
            example: "https://ingressi.example.com/api/auth/callback/corp-idp",
            description: "Register this URI as the redirect URI in the identity provider",
          },
          createdAt: { type: "string", format: "date-time" },
          updatedAt: { type: "string", format: "date-time" },
        },
        required: [
          "id",
          "name",
          "type",
          "clientId",
          "hasClientSecret",
          "scopes",
          "autoLink",
          "enabled",
          "source",
          "callbackUrl",
          "createdAt",
          "updatedAt",
        ],
      },
      OauthProviderInput: {
        type: "object",
        properties: {
          name: { type: "string", example: "Keycloak" },
          type: { type: "string", enum: ["oidc", "oauth2"], default: "oidc" },
          clientId: { type: "string" },
          clientSecret: { type: "string" },
          issuer: { type: "string", example: "https://sso.example.com/realms/main" },
          authorizationUrl: { type: "string" },
          tokenUrl: { type: "string" },
          userinfoUrl: { type: "string" },
          scopes: { type: "string", default: "openid email profile" },
          autoLink: { type: "boolean", default: false },
          enabled: { type: "boolean", default: true },
        },
        required: ["name", "clientId", "clientSecret"],
      },
      OauthProviderUpdate: {
        type: "object",
        description: "All fields optional. Omitting clientSecret preserves the stored secret.",
        properties: {
          name: { type: "string" },
          type: { type: "string", enum: ["oidc", "oauth2"] },
          clientId: { type: "string" },
          clientSecret: { type: "string" },
          issuer: { type: ["string", "null"] },
          authorizationUrl: { type: ["string", "null"] },
          tokenUrl: { type: ["string", "null"] },
          userinfoUrl: { type: ["string", "null"] },
          scopes: { type: "string" },
          autoLink: { type: "boolean" },
          enabled: { type: "boolean" },
        },
      },
      User: {
        type: "object",
        description: "User account (passwordHash is never exposed)",
        properties: {
          id: { type: "integer" },
          email: { type: "string" },
          username: {
            type: ["string", "null"],
            description:
              "Username for the login page, which signs in by username only, ignoring case; null when the account has none. " +
              `${BRAND_NAME} stores only the account's own email address, lowercased, when that is 3-255 characters of a-z 0-9 _ . @ - ` +
              "and no other account signs in with it or has it as email (also for self-registered accounts, whatever username " +
              "the registration asked for), or a username an administrator sets (PUT /api/v1/users/{id}). " +
              "It can be set on an account that has no password yet; the Profile page shows whether password sign-in works",
          },
          name: { type: ["string", "null"] },
          role: {
            type: "string",
            enum: ["admin", "user", "viewer"],
            description:
              "The built-in role. A user with a custom role is stored as viewer, which is also what they fall back to when the custom role is deleted.",
          },
          customRoleId: {
            type: ["integer", "null"],
            description: "The user's custom role (GET /api/v1/roles/{id}), or null for a built-in role",
          },

          provider: { type: "string", example: "credentials" },
          subject: { type: "string" },
          avatarUrl: { type: ["string", "null"] },
          status: { type: "string", enum: ["active", "disabled"] },
          lastSignInAt: {
            type: ["string", "null"],
            format: "date-time",
            description: "When the account last completed a dashboard sign-in; null when it never has",
          },
          lastSignInMethod: {
            type: ["string", "null"],
            enum: ["password", "sso", "saml", "ldap", "passkey", null],
            description: "How that sign-in was made (sso is OAuth/OpenID Connect); null when unknown",
          },
          disabledAt: {
            type: ["string", "null"],
            format: "date-time",
            description: "When the account was disabled; null while it is active, or when the date is unknown (disabled before this was recorded)",
          },
          invited: {
            type: "boolean",
            description:
              "The account is active but nobody has used it yet: it never signed in to the dashboard and none of its API tokens " +
              "was used. Accounts an administrator creates or SCIM provisions start like this.",
          },
          createdAt: { type: "string", format: "date-time" },
          updatedAt: { type: "string", format: "date-time" },
        },
        required: ["id", "email", "role", "provider", "subject", "status", "lastSignInAt", "lastSignInMethod", "disabledAt", "invited", "createdAt", "updatedAt"],
      },
      AuditLogEvent: {
        type: "object",
        properties: {
          id: { type: "integer" },
          userId: { type: ["integer", "null"] },
          action: { type: "string", example: "proxy_host_created" },
          entityType: { type: "string", example: "proxy_host" },
          entityId: { type: ["integer", "null"] },
          summary: { type: ["string", "null"] },
          createdAt: { type: "string", format: "date-time" },
          user: {
            type: ["object", "null"],
            description: "Who acted, as the user is now; null for system events and deleted users",
            properties: { id: { type: "integer" }, name: { type: ["string", "null"] }, email: { type: ["string", "null"] } },
          },
          hash: { type: ["string", "null"] },
          prevHash: { type: ["string", "null"] },
          configChange: {
            type: ["object", "null"],
            description:
              "For a configuration change recorded while configuration history was on: the versions before and after it " +
              "(afterId null while pending, equal to beforeId when nothing changed) and the change request that applied it",
            properties: {
              beforeId: { type: ["integer", "null"] },
              afterId: { type: ["integer", "null"] },
              changeRequestId: { type: ["integer", "null"] },
              pending: { type: "boolean" },
            },
          },
        },
        required: ["id", "action", "entityType", "createdAt"],
      },
      SsoEnforcementInput: {
        type: "object",
        required: ["enabled"],
        properties: {
          enabled: { type: "boolean", description: "Refuse password sign-in for every account except the break-glass accounts" },
          breakGlassUsernames: {
            type: "array",
            maxItems: 20,
            items: { type: "string" },
            description: "Sign-in usernames of the break-glass accounts (case-insensitive), optional: may be empty. Omit to keep the current ones.",
            example: ["admin"],
          },
        },
      },
      SsoEnforcement: {
        type: "object",
        properties: {
          enabled: { type: "boolean" },
          breakGlassUsernames: { type: "array", items: { type: "string" } },
          breakGlassAccounts: {
            type: "array",
            items: {
              type: "object",
              properties: {
                id: { type: "integer" },
                username: { type: ["string", "null"] },
                name: { type: ["string", "null"] },
                email: { type: "string" },
                role: { type: "string", enum: ["admin", "user", "viewer"] },
                status: { type: "string" },
                passwordSignIn: { type: "boolean", description: "Can sign in on the login page with a username and password" },
                validAdmin: {
                  type: "boolean",
                  description:
                    "An active administrator with a password: what the lockout guards count. With none while enforced, the way back in during an outage of the identity provider is turning enforcement off from the host.",
                },
              },
            },
          },
          ssoProviders: {
            type: "array",
            description: "Enabled identity providers that stay available while SSO is enforced",
            items: {
              type: "object",
              properties: {
                id: { type: "string" },
                name: { type: "string" },
                kind: { type: "string", enum: ["oidc", "saml"], description: "saml: id is the provider's accounts providerId, saml:<id>" },
              },
            },
          },
          warnings: { type: "array", items: { type: "string" }, description: "Problems with the setting worth showing an administrator" },
        },
        required: ["enabled", "breakGlassUsernames", "breakGlassAccounts", "ssoProviders", "warnings"],
      },
      CustomRole: {
        type: "object",
        properties: {
          id: { type: "integer" },
          name: { type: "string", maxLength: 64 },
          description: { type: ["string", "null"] },
          permissions: {
            type: "array",
            items: { type: "string", enum: [...PERMISSIONS] },
            description: "In catalogue order; write, restore and import permissions come with the area's read permission",
          },
          scopeTags: {
            type: "array",
            items: { type: "string" },
            description:
              "Tags limiting proxy_hosts, l4_proxy_hosts and certificates permissions to hosts carrying one of them (and the " +
              "certificates those hosts use); empty means every host. Other permissions are not limited.",
          },
          userCount: { type: "integer", description: "Users that have the role" },
          adminLevel: { type: "boolean", description: "Only administrators can create, change or assign it" },
          createdAt: { type: "string", format: "date-time" },
          updatedAt: { type: "string", format: "date-time" },
        },
        required: ["id", "name", "description", "permissions", "scopeTags", "userCount", "adminLevel", "createdAt", "updatedAt"],
      },
      CustomRoleInput: {
        type: "object",
        additionalProperties: false,
        properties: {
          name: {
            type: "string",
            maxLength: 64,
            description: "Required when creating; unique ignoring case; cannot be admin, user or viewer",
          },
          description: { type: ["string", "null"], maxLength: 500 },
          permissions: {
            type: "array",
            items: { type: "string", enum: [...PERMISSIONS] },
            description: "Required when creating. Unknown names are refused (400).",
            example: ["proxy_hosts:write", "certificates:read"],
          },
          scopeTags: {
            type: ["array", "null"],
            items: { type: "string", maxLength: MAX_TAG_LENGTH },
            maxItems: 16,
            description: "Tags to limit the role to (see CustomRole.scopeTags); null or [] for every host",
            example: ["team-a"],
          },
        },
      },
      CustomRoleDeleteResult: {
        type: "object",
        properties: {
          affectedUserIds: {
            type: "array",
            items: { type: "integer" },
            description: "Users that had the role and now have the built-in viewer role",
          },
        },
        required: ["affectedUserIds"],
      },
      PermissionCatalogue: {
        type: "object",
        properties: {
          areas: {
            type: "array",
            items: {
              type: "object",
              properties: {
                area: { type: "string", example: "proxy_hosts" },
                label: { type: "string" },
                description: { type: "string" },
                permissions: { type: "array", items: { type: "string" }, example: ["proxy_hosts:read", "proxy_hosts:write"] },
                scopable: { type: "boolean", description: "A role's scopeTags limit these permissions" },
                instanceWide: { type: "boolean", description: "Reads or changes data of every host, whatever the role's scope" },
              },
              required: ["area", "label", "description", "permissions", "scopable", "instanceWide"],
            },
          },
          adminLevel: {
            type: "object",
            description: "Only administrators can grant these, in a role or by assigning one",
            properties: {
              permissions: { type: "array", items: { type: "string" } },
              combinations: {
                type: "array",
                items: { type: "array", items: { type: "string" } },
                description: "Sets of permissions that are administrator-level together",
              },
            },
            required: ["permissions", "combinations"],
          },
          unscopedOnly: {
            type: "array",
            items: { type: "string" },
            description: "Permissions a role with scopeTags cannot hold: they read or replace every host's configuration at once",
          },
        },
        required: ["areas", "adminLevel", "unscopedOnly"],
      },
      MfaStatus: {
        type: "object",
        description: "An account's multi-factor authentication state. Never includes the authenticator secret or backup codes.",
        properties: {
          enabled: {
            type: "boolean",
            description:
              "MFA is on: the account has an authenticator app or a passkey, and every password sign-in asks for a second factor",
          },
          authenticatorApp: { type: "boolean", description: "An authenticator app (TOTP) is set up" },
          passkeys: { type: "integer", description: "How many passkeys the account has; a passkey counts as a second factor" },
          backupCodesRemaining: { type: ["integer", "null"], description: "Unused backup codes; null when the authenticator app is off" },
          hasPassword: { type: "boolean", description: "The account has a password, so it can set up MFA" },
          required: { type: "boolean", description: "The MFA policy requires this account to use MFA" },
          gate: {
            type: "string",
            enum: ["none", "prompt", "required"],
            description: "none: nothing to do; prompt: set up MFA before the deadline; required: the grace period is over and dashboard sessions can only set up MFA",
          },
          deadline: { type: ["string", "null"], format: "date-time", description: "When a required account must have set up MFA" },
        },
        required: ["enabled", "authenticatorApp", "passkeys", "backupCodesRemaining", "hasPassword", "required", "gate", "deadline"],
      },
      MfaPolicyInput: {
        type: "object",
        required: ["scope"],
        additionalProperties: false,
        properties: {
          scope: {
            type: "string",
            enum: ["off", "admins", "password_users"],
            description: "off: nobody is required to use MFA; admins: administrators; password_users: every account that can sign in with a password",
          },
          graceDays: {
            type: "integer",
            minimum: 0,
            maximum: 90,
            description: "Days after the scope takes effect during which covered accounts are asked, but not forced, to set up MFA. Omit to keep the current value (default 7).",
          },
        },
      },
      MfaPolicy: {
        type: "object",
        properties: {
          scope: { type: "string", enum: ["off", "admins", "password_users"] },
          graceDays: { type: "integer" },
          since: { type: ["string", "null"], format: "date-time", description: "When the current scope took effect; null while off" },
          deadline: { type: ["string", "null"], format: "date-time", description: "End of the grace period; null while off" },
          accounts: {
            type: "object",
            properties: {
              required: { type: "integer", description: "Accounts the policy covers" },
              enrolled: { type: "integer", description: "Covered accounts with MFA on" },
              pending: {
                type: "array",
                description: "Covered accounts without MFA",
                items: {
                  type: "object",
                  properties: {
                    id: { type: "integer" },
                    username: { type: ["string", "null"] },
                    name: { type: ["string", "null"] },
                    email: { type: "string" },
                    role: { type: "string", enum: ["admin", "user", "viewer"] },
                    enabled: { type: "boolean" },
                    required: { type: "boolean" },
                    gate: { type: "string", enum: ["none", "prompt", "required"] },
                  },
                },
              },
            },
            required: ["required", "enrolled", "pending"],
          },
        },
        required: ["scope", "graceDays", "since", "deadline", "accounts"],
      },
      ConfigSnapshot: {
        type: "object",
        properties: {
          id: { type: "integer" },
          createdAt: { type: "string", format: "date-time" },
          userId: { type: ["integer", "null"], description: "Who caused the snapshot; null for automatic snapshots" },
          userName: { type: ["string", "null"] },
          reason: {
            type: "string",
            enum: ["auto", "manual", "before_restore", "import"],
            description: "auto: after an applied change; before_restore / import: the configuration a restore or an import replaced",
          },
          summary: { type: "string" },
          fingerprint: { type: "string", description: "SHA-256 of the canonical content" },
          sizeBytes: { type: "integer" },
        },
        required: ["id", "createdAt", "userId", "userName", "reason", "summary", "fingerprint", "sizeBytes"],
      },
      ConfigSnapshotList: {
        type: "object",
        properties: {
          snapshots: { type: "array", items: { $ref: "#/components/schemas/ConfigSnapshot" } },
          total: { type: "integer" },
          limit: { type: "integer" },
          offset: { type: "integer" },
        },
        required: ["snapshots", "total", "limit", "offset"],
      },
      ConfigCounts: {
        type: "object",
        description: "Rows per entity type, and the number of settings groups that are set",
        additionalProperties: { type: "integer" },
        example: { proxyHosts: 4, l4ProxyHosts: 1, certificates: 2, settings: 5 },
      },
      ConfigSnapshotDetail: {
        allOf: [
          { $ref: "#/components/schemas/ConfigSnapshot" },
          {
            type: "object",
            properties: {
              content: {
                type: "object",
                properties: {
                  counts: { $ref: "#/components/schemas/ConfigCounts" },
                  items: {
                    type: "object",
                    description: "Per entity type, the id and name of every item",
                    additionalProperties: {
                      type: "array",
                      items: { type: "object", properties: { id: { type: "integer" }, label: { type: "string" } } },
                    },
                  },
                  settings: { type: "array", items: { type: "string" }, description: "Settings groups that are set" },
                },
              },
            },
          },
        ],
      },
      ConfigHistorySettings: {
        type: "object",
        properties: {
          enabled: { type: "boolean", description: "Record a snapshot after every applied change" },
          retention: { type: "integer", description: "Snapshots kept; older ones are deleted", default: 200 },
        },
        required: ["enabled", "retention"],
      },
      ConfigFieldChange: {
        type: "object",
        properties: {
          path: { type: "string", description: "Column, or dotted path into a JSON column or settings group" },
          before: {},
          after: {},
          secret: { type: "boolean", enum: [true], description: "A secret changed; before and after are omitted" },
        },
        required: ["path"],
      },
      ConfigEntityDiff: {
        type: "object",
        properties: {
          entity: {
            type: "string",
            enum: [
              "certificates", "caCertificates", "issuedClientCertificates", "accessLists", "accessListEntries",
              "proxyHosts", "l4ProxyHosts", "mtlsRoles", "mtlsCertificateRoles", "mtlsAccessRules", "groups",
              "forwardAuthAccess", "settings",
            ],
          },
          label: { type: "string" },
          added: { type: "array", items: { type: "object", properties: { id: {}, label: { type: "string" } } } },
          removed: { type: "array", items: { type: "object", properties: { id: {}, label: { type: "string" } } } },
          changed: {
            type: "array",
            items: {
              type: "object",
              properties: {
                id: {},
                label: { type: "string" },
                changes: { type: "array", items: { $ref: "#/components/schemas/ConfigFieldChange" } },
              },
            },
          },
        },
        required: ["entity", "label", "added", "removed", "changed"],
      },
      ConfigSnapshotDiff: {
        type: "object",
        properties: {
          snapshot: { $ref: "#/components/schemas/ConfigSnapshot" },
          against: {
            type: "object",
            properties: {
              kind: { type: "string", enum: ["current", "snapshot", "empty"] },
              id: { type: "integer", description: "Set when kind is snapshot" },
            },
            required: ["kind"],
          },
          diff: {
            type: "object",
            properties: {
              entities: { type: "array", items: { $ref: "#/components/schemas/ConfigEntityDiff" } },
              totals: {
                type: "object",
                properties: { added: { type: "integer" }, removed: { type: "integer" }, changed: { type: "integer" } },
              },
            },
            required: ["entities", "totals"],
          },
        },
        required: ["snapshot", "against", "diff"],
      },
      ConfigRestoreResult: {
        type: "object",
        properties: {
          restoredSnapshotId: { type: "integer" },
          beforeSnapshotId: { type: "integer", description: "Snapshot of the configuration the restore replaced" },
          warning: { type: ["string", "null"], description: "Set when Caddy applied the configuration but syncing slaves failed" },
        },
        required: ["restoredSnapshotId", "beforeSnapshotId", "warning"],
      },
      ConfigExportFile: {
        type: "object",
        properties: {
          format: { type: "string", enum: ["ingressi-configuration"] },
          version: { type: "integer", enum: [1] },
          exportedAt: { type: "string", format: "date-time" },
          appVersion: { type: "string" },
          kdf: {
            type: "object",
            properties: {
              name: { type: "string", enum: ["scrypt"] },
              N: { type: "integer" },
              r: { type: "integer" },
              p: { type: "integer" },
              salt: { type: "string", description: "Base64" },
            },
          },
          cipher: { type: "string", enum: ["aes-256-gcm"] },
          check: { type: "string", description: "A known value sealed with the passphrase, to recognize a wrong passphrase" },
          users: {
            type: "object",
            additionalProperties: { type: "string" },
            description: "Email address of each user a forward-auth grant names, by user id",
          },
          content: {
            type: "object",
            description:
              "version, tables (rows per entity type, as stored) and settings (settings groups by storage key). " +
              'Secrets are strings of the form "pp:v1:<iv>:<tag>:<ciphertext>".',
          },
        },
        required: ["format", "version", "exportedAt", "appVersion", "kdf", "cipher", "check", "users", "content"],
      },
      ConfigImportResult: {
        type: "object",
        properties: {
          ok: { type: "boolean", enum: [true] },
          counts: { $ref: "#/components/schemas/ConfigCounts" },
          warning: { type: ["string", "null"] },
          beforeSnapshotId: {
            type: ["integer", "null"],
            description: "Snapshot of the replaced configuration, when configuration history is on",
          },
        },
        required: ["ok", "counts", "warning", "beforeSnapshotId"],
      },
      AlertChannel: {
        type: "object",
        properties: {
          id: { type: "integer" },
          name: { type: "string" },
          type: { type: "string", enum: ["email", "slack", "teams", "webhook", "pagerduty", "ntfy", "telegram"] },
          enabled: { type: "boolean" },
          config: {
            description: "Non-secret settings of the channel type; credentials appear only as has* flags.",
            oneOf: [
              {
                title: "email",
                type: "object",
                properties: {
                  host: { type: "string" },
                  port: { type: "integer" },
                  secure: { type: "boolean", description: "Implicit TLS (port 465); otherwise STARTTLS is used when offered" },
                  user: { type: ["string", "null"] },
                  from: { type: "string" },
                  to: { type: "array", items: { type: "string" } },
                  hasPassword: { type: "boolean" },
                },
              },
              {
                title: "slack / teams",
                type: "object",
                properties: { hasWebhookUrl: { type: "boolean" }, webhookUrlHint: { type: ["string", "null"], example: "https://hooks.slack.com" } },
              },
              {
                title: "webhook",
                type: "object",
                properties: { hasUrl: { type: "boolean" }, urlHint: { type: ["string", "null"] }, hasHmacSecret: { type: "boolean" } },
              },
              { title: "pagerduty", type: "object", properties: { region: { type: "string", enum: ["us", "eu"] }, hasRoutingKey: { type: "boolean" } } },
              {
                title: "ntfy",
                type: "object",
                properties: { serverUrl: { type: "string" }, topic: { type: "string" }, hasToken: { type: "boolean" } },
              },
              { title: "telegram", type: "object", properties: { chatId: { type: "string" }, hasBotToken: { type: "boolean" } } },
            ],
          },
          lastDeliveryAt: { type: ["string", "null"], format: "date-time" },
          lastDeliveryError: { type: ["string", "null"] },
          createdAt: { type: "string", format: "date-time" },
          updatedAt: { type: "string", format: "date-time" },
        },
        required: ["id", "name", "type", "enabled", "config", "lastDeliveryAt", "lastDeliveryError", "createdAt", "updatedAt"],
      },
      AlertChannelConfigInput: {
        type: "object",
        description: "Fields of the channel's type only; unknown fields are rejected.",
        additionalProperties: false,
        properties: {
          host: { type: "string", description: "email: SMTP server" },
          port: { type: "integer", description: "email: default 587, or 465 with secure" },
          secure: { type: "boolean", description: "email: implicit TLS" },
          user: { type: ["string", "null"], description: "email: SMTP user name" },
          password: { type: ["string", "null"], writeOnly: true, description: "email: SMTP password" },
          from: { type: "string", format: "email", description: "email: sender address" },
          to: { type: "array", items: { type: "string", format: "email" }, maxItems: 20, description: "email: recipients" },
          webhookUrl: { type: "string", writeOnly: true, description: "slack / teams: incoming webhook or Teams Workflows URL (https)" },
          url: { type: "string", writeOnly: true, description: "webhook: http(s) URL" },
          hmacSecret: {
            type: ["string", "null"],
            writeOnly: true,
            description: "webhook: when set, requests carry X-Ingressi-Timestamp and X-Ingressi-Signature: sha256=HMAC-SHA256(secret, timestamp + \".\" + body)",
          },
          routingKey: { type: "string", writeOnly: true, description: "pagerduty: Events API v2 integration key" },
          region: { type: "string", enum: ["us", "eu"], description: "pagerduty: service region, default us" },
          serverUrl: { type: "string", description: "ntfy: server, default https://ntfy.sh" },
          topic: { type: "string", description: "ntfy: topic" },
          token: { type: ["string", "null"], writeOnly: true, description: "ntfy: access token" },
          chatId: { type: "string", description: "telegram: numeric chat id or public channel name (@channel)" },
          botToken: { type: "string", writeOnly: true, description: "telegram: bot token from @BotFather" },
        },
      },
      AlertChannelInput: {
        type: "object",
        additionalProperties: false,
        properties: {
          name: { type: "string", maxLength: 100 },
          type: { type: "string", enum: ["email", "slack", "teams", "webhook", "pagerduty", "ntfy", "telegram"] },
          enabled: { type: "boolean", default: true },
          config: { $ref: "#/components/schemas/AlertChannelConfigInput" },
        },
        required: ["name", "type", "config"],
      },
      AlertChannelUpdate: {
        type: "object",
        additionalProperties: false,
        properties: {
          name: { type: "string", maxLength: 100 },
          enabled: { type: "boolean" },
          config: { $ref: "#/components/schemas/AlertChannelConfigInput" },
        },
      },
      AlertDeliveryResult: {
        type: "object",
        properties: { ok: { type: "boolean" }, error: { type: ["string", "null"] } },
        required: ["ok", "error"],
      },
      AlertRuleParams: {
        type: "object",
        description:
          "Depends on the type. cert_expiring: days (1-365, default 14), includeClientCertificates (default true), includeManagedCertificates " +
          "(default true: also the certificates Caddy obtains through ACME, read from Caddy with a TLS handshake; they also fire when their renewal is overdue " +
          "or Caddy has no certificate for a domain). upstream_down: minFails (default 1). " +
          "waf_spike: threshold (default 100), windowMinutes (1-1440, default 15). error_rate: thresholdPercent (0.1-100, one decimal, default 5), " +
          "windowMinutes (1-1440, default 5), minRequests (default 20), perHost (default true: one alert per proxy host; false: the hosts in scope together); " +
          "needs ClickHouse analytics. " +
          "backup_failed: minFailures (1-100, default 1), consecutive failed backups to one destination. instance_sync_failed, caddy_apply_failed, approval_pending, access_review_started, access_review_overdue, fleet_drift, fleet_rollout_failed: none.",
        additionalProperties: false,
        properties: {
          days: { type: "integer", minimum: 1, maximum: 365 },
          includeClientCertificates: { type: "boolean" },
          includeManagedCertificates: { type: "boolean" },
          minFails: { type: "integer", minimum: 1, maximum: 1000 },
          thresholdPercent: { type: "number", minimum: 0.1, maximum: 100 },
          minRequests: { type: "integer", minimum: 1, maximum: 10000000 },
          perHost: { type: "boolean" },
          threshold: { type: "integer", minimum: 1 },
          windowMinutes: { type: "integer", minimum: 1, maximum: 1440 },
          minFailures: { type: "integer", minimum: 1, maximum: 100 },
        },
      },
      AlertRule: {
        type: "object",
        properties: {
          id: { type: "integer" },
          builtIn: {
            type: ["string", "null"],
            description: "Key of a built-in rule (every install has them; they notify nobody until channels are added); null for rules people created. Built-in rules can be changed and disabled, not deleted.",
          },
          name: { type: "string" },
          type: { type: "string", enum: ["cert_expiring", "upstream_down", "waf_spike", "error_rate", "instance_sync_failed", "caddy_apply_failed", "backup_failed", "approval_pending", "access_review_started", "access_review_overdue", "fleet_drift", "fleet_rollout_failed"] },
          enabled: { type: "boolean" },
          params: { $ref: "#/components/schemas/AlertRuleParams" },
          channelIds: { type: "array", items: { type: "integer" } },
          cooldownMinutes: { type: "integer", description: "Minimum time between two firing notifications for the same subject" },
          notifyOnResolve: { type: "boolean", description: "Send a notice when the condition clears (PagerDuty incidents are always resolved)" },
          explain: { type: "boolean", description: "Append an AI-generated explanation (AI analyst)" },
          scope: { $ref: "#/components/schemas/AlertRuleScope" },
          scopeLabel: { type: "string", description: "What the rule watches, in words", example: "Each proxy host" },
          forMinutes: { type: "integer", description: "Minutes the condition must hold before the rule fires; 0 fires at once" },
          firing: {
            type: "array",
            items: {
              type: "object",
              properties: {
                subjectKey: { type: "string", example: "certificate:3" },
                title: { type: ["string", "null"] },
                firedAt: { type: ["string", "null"], format: "date-time" },
              },
            },
          },
          pending: {
            type: "array",
            description: "Subjects whose condition holds but has not lasted forMinutes yet",
            items: {
              type: "object",
              properties: {
                subjectKey: { type: "string" },
                title: { type: ["string", "null"] },
                since: { type: ["string", "null"], format: "date-time" },
              },
            },
          },
          lastFiredAt: {
            type: ["string", "null"],
            format: "date-time",
            description: "When the rule last fired (its newest firing event in the 90-day history); null when it has not",
          },
          mute: { oneOf: [{ $ref: "#/components/schemas/AlertSilence" }, { type: "null" }], description: "The rule's mute in effect" },
          createdAt: { type: "string", format: "date-time" },
          updatedAt: { type: "string", format: "date-time" },
        },
        required: ["id", "name", "type", "enabled", "params", "channelIds", "cooldownMinutes", "notifyOnResolve", "explain", "scope", "scopeLabel", "forMinutes", "firing", "pending", "lastFiredAt", "mute", "createdAt", "updatedAt"],
      },
      AlertSilence: {
        type: "object",
        properties: {
          id: { type: "integer" },
          kind: { type: "string", enum: ["mute", "dismissal"], description: "mute: every alert of the rule; dismissal: one alert" },
          ruleId: { type: "integer" },
          ruleName: { type: "string" },
          subjectKey: { type: ["string", "null"], description: "The dismissed alert; null for a mute", example: "certificate:3" },
          subjectTitle: { type: ["string", "null"], description: "What the dismissed alert is about, while it fires" },
          until: { type: ["string", "null"], format: "date-time", description: "When it ends; null for a dismissal that lasts until the alert resolves" },
          note: { type: ["string", "null"] },
          createdBy: { type: ["integer", "null"], description: "The user who created it" },
          createdByName: { type: ["string", "null"] },
          createdAt: { type: "string", format: "date-time" },
        },
        required: ["id", "kind", "ruleId", "ruleName", "subjectKey", "subjectTitle", "until", "note", "createdBy", "createdByName", "createdAt"],
      },
      AlertSilenceInput: {
        type: "object",
        additionalProperties: false,
        properties: {
          ruleId: { type: "integer" },
          subjectKey: { type: "string", maxLength: 500, description: "The alert to dismiss (as in /api/v1/alert-events/firing); omitted: mute the whole rule" },
          until: { type: "string", format: "date-time", description: "When it ends, at most 30 days ahead" },
          durationMinutes: { type: "integer", minimum: 1, maximum: 43200, description: "How long it lasts, instead of until" },
          note: { type: "string", maxLength: 500 },
        },
        required: ["ruleId"],
      },
      AlertRuleScope: {
        description:
          "Which proxy hosts the rule watches. Only cert_expiring (certificates of those hosts; CA and client certificates only without a host list), " +
          "upstream_down (their upstreams), waf_spike and error_rate accept a host list; every other type watches what it always watched.",
        oneOf: [
          { type: "object", additionalProperties: false, properties: { type: { const: "all" } }, required: ["type"] },
          {
            type: "object",
            additionalProperties: false,
            properties: { type: { const: "hosts" }, proxyHostIds: { type: "array", items: { type: "integer" }, minItems: 1, maxItems: 200 } },
            required: ["type", "proxyHostIds"],
          },
        ],
      },
      FiringAlert: {
        type: "object",
        properties: {
          ruleId: { type: "integer" },
          ruleName: { type: "string" },
          ruleType: { type: "string" },
          subjectKey: { type: "string" },
          severity: { type: "string", enum: ["critical", "warning", "info"] },
          title: { type: "string" },
          message: { type: "string" },
          firedAt: { type: ["string", "null"], format: "date-time" },
          deliveries: {
            type: "array",
            items: {
              type: "object",
              properties: {
                channelId: { type: "integer" },
                channelName: { type: "string" },
                ok: { type: "boolean" },
                error: { type: ["string", "null"] },
              },
            },
          },
          silenced: { type: ["string", "null"], enum: ["muted", "dismissed", null], description: "Nothing was sent when it fired because the rule was muted or the alert dismissed" },
          eventId: { type: ["integer", "null"] },
          notifyOnResolve: { type: "boolean" },
          dismissal: { oneOf: [{ $ref: "#/components/schemas/AlertSilence" }, { type: "null" }], description: "The alert's dismissal in effect" },
          mute: { oneOf: [{ $ref: "#/components/schemas/AlertSilence" }, { type: "null" }], description: "Its rule's mute in effect" },
          links: {
            type: "array",
            description: "Dashboard pages that deal with it, each with the permission needed to open it",
            items: { type: "object", properties: { label: { type: "string" }, route: { type: "string" }, permission: { type: "string" } } },
          },
        },
      },
      AlertRuleInput: {
        type: "object",
        additionalProperties: false,
        properties: {
          name: { type: "string", maxLength: 100 },
          type: { type: "string", enum: ["cert_expiring", "upstream_down", "waf_spike", "error_rate", "instance_sync_failed", "caddy_apply_failed", "backup_failed", "approval_pending", "access_review_started", "access_review_overdue", "fleet_drift", "fleet_rollout_failed"] },
          enabled: { type: "boolean", default: true },
          params: { $ref: "#/components/schemas/AlertRuleParams" },
          channelIds: { type: "array", items: { type: "integer" }, maxItems: 20 },
          cooldownMinutes: { type: "integer", minimum: 0, maximum: 10080, default: 60 },
          notifyOnResolve: { type: "boolean", default: true },
          explain: { type: "boolean", default: false },
          scope: { $ref: "#/components/schemas/AlertRuleScope" },
          forMinutes: {
            type: "integer",
            minimum: 0,
            maximum: 1440,
            default: 0,
            description: "Minutes the condition must hold before the rule fires; only for cert_expiring, upstream_down, waf_spike, error_rate, instance_sync_failed, caddy_apply_failed, backup_failed and fleet_drift",
          },
        },
        required: ["name", "type"],
      },
      AlertRuleUpdate: {
        type: "object",
        additionalProperties: false,
        properties: {
          name: { type: "string", maxLength: 100 },
          enabled: { type: "boolean" },
          params: { $ref: "#/components/schemas/AlertRuleParams" },
          channelIds: { type: "array", items: { type: "integer" }, maxItems: 20 },
          cooldownMinutes: { type: "integer", minimum: 0, maximum: 10080 },
          notifyOnResolve: { type: "boolean" },
          explain: { type: "boolean" },
          scope: { $ref: "#/components/schemas/AlertRuleScope" },
          forMinutes: { type: "integer", minimum: 0, maximum: 1440 },
        },
      },
      AlertEvent: {
        type: "object",
        properties: {
          id: { type: "integer" },
          ruleId: { type: "integer" },
          ruleName: { type: "string" },
          ruleType: { type: "string" },
          subjectKey: { type: "string" },
          status: { type: "string", enum: ["firing", "resolved"] },
          severity: { type: "string", enum: ["critical", "warning", "info"] },
          title: { type: "string" },
          message: { type: "string" },
          explanation: { type: ["string", "null"], description: "AI-generated explanation, when one was produced" },
          notified: { type: "boolean", description: "False when suppressed by the cooldown, a mute or a dismissal, or when the rule has no channels" },
          deliveries: {
            type: "array",
            items: {
              type: "object",
              properties: {
                channelId: { type: "integer" },
                channelName: { type: "string" },
                ok: { type: "boolean" },
                error: { type: ["string", "null"] },
              },
            },
          },
          createdAt: { type: "string", format: "date-time" },
          resolvedAt: { type: ["string", "null"], format: "date-time", description: "For a firing event: when that episode resolved; null while it fires" },
          silenced: {
            type: ["string", "null"],
            enum: ["muted", "dismissed", null],
            description: "Not notified because the rule was muted or the alert dismissed (for a resolve: its firing notification was held back so)",
          },
        },
        required: ["id", "ruleId", "ruleName", "ruleType", "subjectKey", "status", "severity", "title", "message", "explanation", "notified", "deliveries", "createdAt", "resolvedAt", "silenced"],
      },
      AlertEventsResponse: {
        type: "object",
        properties: {
          events: { type: "array", items: { $ref: "#/components/schemas/AlertEvent" } },
          total: { type: "integer" },
          page: { type: "integer" },
          perPage: { type: "integer" },
        },
        required: ["events", "total", "page", "perPage"],
      },
      AiSettings: {
        type: "object",
        properties: {
          enabled: { type: "boolean" },
          provider: { type: ["string", "null"], enum: ["anthropic", "openai_compatible", null] },
          model: { type: ["string", "null"] },
          baseUrl: { type: ["string", "null"], description: "openai_compatible only" },
          hasApiKey: { type: "boolean" },
          timeoutSeconds: {
            type: "integer",
            minimum: 5,
            maximum: 300,
            description: "How long one model call (alert explanation, digest summary, analytics question, test) may take; 60 when never set",
          },
          configured: { type: "boolean", description: "Enabled and complete: rules with explain=true get explanations" },
          defaultModel: { type: "string", description: "Default model for the anthropic provider" },
        },
        required: ["enabled", "provider", "model", "baseUrl", "hasApiKey", "timeoutSeconds", "configured", "defaultModel"],
      },
      AiSettingsInput: {
        type: "object",
        additionalProperties: false,
        properties: {
          enabled: { type: "boolean", default: true },
          provider: { type: ["string", "null"], enum: ["anthropic", "openai_compatible", null], description: "null removes the provider (no other fields allowed)" },
          model: { type: "string", description: "Defaults to claude-opus-5 for anthropic; required for openai_compatible" },
          apiKey: { type: ["string", "null"], writeOnly: true, description: "Required for anthropic, optional for openai_compatible" },
          baseUrl: { type: "string", description: "openai_compatible only, e.g. http://ollama:11434/v1; requests go to {baseUrl}/chat/completions" },
          timeoutSeconds: {
            type: "integer",
            minimum: 5,
            maximum: 300,
            default: 60,
            description: "How long one model call may take before it is given up. Omit to keep the current value.",
          },
        },
      },
      AiTestResult: {
        type: "object",
        properties: {
          ok: { type: "boolean" },
          explanation: { type: ["string", "null"] },
          error: { type: ["string", "null"] },
        },
        required: ["ok", "explanation", "error"],
      },
      AiDigestDelivery: {
        type: "object",
        properties: {
          channelId: { type: "integer" },
          channelName: { type: "string" },
          ok: { type: "boolean" },
          error: { type: ["string", "null"] },
        },
        required: ["channelId", "channelName", "ok", "error"],
      },
      AiDigestNarrative: {
        type: "object",
        properties: {
          status: { type: "string", enum: ["added", "off", "unavailable", "failed"], description: "added; off (not asked for); unavailable (no provider configured); failed (error, timeout or refusal: the plain digest is used)" },
          error: { type: ["string", "null"] },
        },
        required: ["status", "error"],
      },
      AiDigestSettings: {
        type: "object",
        properties: {
          enabled: { type: "boolean" },
          timeOfDay: { type: "string", pattern: "^([01][0-9]|2[0-3]):[0-5][0-9]$", example: "08:00" },
          timeZone: { type: "string", description: "IANA time zone", example: "Europe/Rome" },
          channelIds: { type: "array", items: { type: "integer" } },
          ai: { type: "boolean", description: "Add an AI-generated summary when a provider is configured" },
          nextRunAt: { type: ["string", "null"], format: "date-time" },
          lastRun: {
            type: ["object", "null"],
            properties: {
              at: { type: "string", format: "date-time" },
              trigger: { type: "string", enum: ["scheduled", "manual"] },
              narrative: { type: "string", enum: ["added", "off", "unavailable", "failed"] },
              deliveries: { type: "array", items: { $ref: "#/components/schemas/AiDigestDelivery" } },
            },
            required: ["at", "trigger", "narrative", "deliveries"],
          },
        },
        required: ["enabled", "timeOfDay", "timeZone", "channelIds", "ai", "nextRunAt", "lastRun"],
      },
      AiDigestSettingsInput: {
        type: "object",
        additionalProperties: false,
        properties: {
          enabled: { type: "boolean" },
          timeOfDay: { type: "string", example: "08:00", description: "24-hour time in timeZone; default 08:00" },
          timeZone: { type: "string", example: "Europe/Rome", description: "IANA time zone; default UTC" },
          channelIds: { type: "array", items: { type: "integer" }, maxItems: 20, description: "Alert channel ids (not PagerDuty); at least one when enabled" },
          ai: { type: "boolean", description: "Default false" },
        },
      },
      AiDigestPreview: {
        type: "object",
        properties: {
          subject: { type: "string" },
          text: { type: "string" },
          html: { type: "string" },
          narrative: { $ref: "#/components/schemas/AiDigestNarrative" },
          facts: { type: "object", description: "The aggregated facts the digest was built from (and the model saw)" },
        },
        required: ["subject", "text", "html", "narrative", "facts"],
      },
      AiDigestSendResult: {
        type: "object",
        properties: {
          narrative: { $ref: "#/components/schemas/AiDigestNarrative" },
          deliveries: { type: "array", items: { $ref: "#/components/schemas/AiDigestDelivery" } },
        },
        required: ["narrative", "deliveries"],
      },
      WafTuningSuggestion: {
        type: "object",
        properties: {
          id: { type: "string", example: "942100-1a2b3c4d5e6f" },
          host: { type: "string", description: "Request host the rule matched on" },
          proxyHost: { type: "object", properties: { id: { type: "integer" }, name: { type: "string" } }, required: ["id", "name"] },
          ruleId: { type: "integer" },
          ruleMessage: { type: ["string", "null"] },
          ruleFamily: { type: ["string", "null"], example: "SQL injection" },
          attackCritical: { type: "boolean", description: "Attack-critical rule family; such suggestions are never high confidence" },
          confidence: { type: "string", enum: ["high", "medium", "low"] },
          score: { type: "integer", minimum: 0, maximum: 100 },
          reasons: { type: "array", items: { type: "string" } },
          exclusion: {
            type: "object",
            properties: {
              type: { type: "string", enum: ["host_rule_suppression"] },
              proxyHostId: { type: "integer" },
              ruleId: { type: "integer" },
              description: { type: "string" },
            },
            required: ["type", "proxyHostId", "ruleId", "description"],
          },
          evidence: {
            type: "object",
            properties: {
              windowDays: { type: "integer" },
              events: { type: "integer" },
              clients: { type: "integer" },
              activeDays: { type: "integer" },
              blockedEvents: { type: "integer" },
              detectionOnlyEvents: { type: "integer" },
              criticalEvents: { type: "integer" },
              averageAnomalyScore: { type: ["number", "null"] },
              cleanClients: { type: "integer", description: "Clients that triggered no other WAF rule" },
              normalClients: { type: ["integer", "null"], description: "Clients with successful requests to the same host; null without traffic data" },
              firstSeen: { type: "string", format: "date-time" },
              lastSeen: { type: "string", format: "date-time" },
              pathPrefixes: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    prefix: { type: "string" },
                    events: { type: "integer" },
                    clients: { type: "integer" },
                    examplePaths: { type: "array", items: { type: "string" }, description: "Query strings removed" },
                  },
                  required: ["prefix", "events", "clients", "examplePaths"],
                },
              },
            },
            required: ["windowDays", "events", "clients", "activeDays", "blockedEvents", "detectionOnlyEvents", "criticalEvents", "averageAnomalyScore", "cleanClients", "normalClients", "firstSeen", "lastSeen", "pathPrefixes"],
          },
          explanation: {
            type: ["object", "null"],
            properties: { label: { type: "string", enum: ["AI-generated risk assessment"] }, text: { type: "string" } },
            required: ["label", "text"],
          },
          status: { type: "string", enum: ["open", "applied", "dismissed"] },
          generatedAt: { type: "string", format: "date-time" },
        },
        required: ["id", "host", "proxyHost", "ruleId", "ruleMessage", "ruleFamily", "attackCritical", "confidence", "score", "reasons", "exclusion", "evidence", "explanation", "status", "generatedAt"],
      },
      WafTuningResult: {
        type: "object",
        properties: {
          analyticsEnabled: { type: "boolean", description: "False when ClickHouse analytics is not configured (no suggestions)" },
          windowDays: { type: "integer" },
          generatedAt: { type: "string", format: "date-time" },
          suggestions: { type: "array", items: { $ref: "#/components/schemas/WafTuningSuggestion" } },
          error: { type: ["string", "null"], description: "Set when ClickHouse could not be queried; the stored suggestions are left as they were" },
          explanationError: { type: ["string", "null"], description: "Why some requested risk assessments are missing" },
        },
        required: ["analyticsEnabled", "windowDays", "generatedAt", "suggestions", "error", "explanationError"],
      },
      WafTuningApplyResult: {
        type: "object",
        properties: {
          suggestion: { $ref: "#/components/schemas/WafTuningSuggestion" },
          proxyHost: { type: "object", properties: { id: { type: "integer" }, name: { type: "string" } }, required: ["id", "name"] },
          warning: { type: ["string", "null"], description: "Set when the exclusion was saved but Caddy could not be reconfigured" },
        },
        required: ["suggestion", "proxyHost", "warning"],
      },
      AuditLogResponse: {
        type: "object",
        properties: {
          events: { type: "array", items: { $ref: "#/components/schemas/AuditLogEvent" } },
          total: { type: "integer" },
          page: { type: "integer" },
          perPage: { type: "integer" },
        },
        required: ["events", "total", "page", "perPage"],
      },
      AuditLogExportEvent: {
        type: "object",
        description: "An exported event. data is the stored text exactly as hashed.",
        properties: {
          id: { type: "integer" },
          createdAt: { type: "string", format: "date-time" },
          userId: { type: ["integer", "null"] },
          userEmail: { type: ["string", "null"] },
          userName: { type: ["string", "null"] },
          action: { type: "string" },
          entityType: { type: "string" },
          entityId: { type: ["integer", "null"] },
          summary: { type: ["string", "null"] },
          data: { type: ["string", "null"] },
          prevHash: { type: ["string", "null"] },
          hash: { type: ["string", "null"], description: "Null on events recorded before the hash chain existed" },
          actorDigest: { type: ["string", "null"] },
        },
      },
      AuditLogExport: {
        type: "object",
        properties: {
          exportedAt: { type: "string", format: "date-time" },
          from: { type: ["string", "null"], format: "date-time" },
          to: { type: ["string", "null"], format: "date-time" },
          hashChain: {
            type: "object",
            properties: { version: { type: "integer" }, algorithm: { type: "string", example: "sha256" } },
          },
          events: { type: "array", items: { $ref: "#/components/schemas/AuditLogExportEvent" } },
        },
      },
      AuditVerification: {
        type: "object",
        properties: {
          ok: { type: "boolean" },
          checked: { type: "integer", description: "Chained events checked, up to and including the first mismatch" },
          firstMismatchId: { type: ["integer", "null"] },
          reason: { type: ["string", "null"], description: "Why firstMismatchId failed" },
          anchoredAt: { type: ["string", "null"], format: "date-time", description: "createdAt of the oldest remaining chained event" },
          anchorId: { type: ["integer", "null"] },
          anchorHash: { type: ["string", "null"], description: "prevHash of the anchor event, trusted as the starting point" },
          headId: { type: ["integer", "null"] },
          headHash: { type: ["string", "null"], description: "Compare with a streamed or exported copy to detect deleted recent events" },
          unchainedEvents: { type: "integer", description: "Events recorded before the hash chain existed" },
          verifiedAt: { type: "string", format: "date-time" },
        },
        required: ["ok", "checked", "firstMismatchId", "anchoredAt"],
      },
      AuditRetention: {
        type: "object",
        properties: {
          days: { type: "integer", minimum: 0, maximum: 36500, description: "0 keeps events forever" },
          lastRunAt: { type: ["string", "null"], format: "date-time" },
          lastDeleted: { type: ["integer", "null"] },
        },
        required: ["days"],
      },
      AuditRetentionInput: {
        type: "object",
        properties: { days: { type: "integer", minimum: 0, maximum: 36500 } },
        required: ["days"],
      },
      WebhookSinkConfig: {
        type: "object",
        description:
          "POSTs {\"events\": [...]} with X-Ingressi-Timestamp and X-Ingressi-Signature: sha256=hex(HMAC-SHA256(secret, timestamp + \".\" + body)).",
        properties: { url: { type: "string", format: "uri", example: "https://siem.example.com/ingest" } },
        required: ["url"],
      },
      SplunkHecSinkConfig: {
        type: "object",
        description:
          "POSTs newline-delimited events with sourcetype ingressi:audit to <url>/services/collector/event, with Authorization: Splunk <secret>.",
        properties: {
          url: { type: "string", format: "uri", example: "https://splunk.example.com:8088" },
          index: { type: ["string", "null"] },
        },
        required: ["url"],
      },
      SyslogSinkConfig: {
        type: "object",
        description:
          "RFC 5424 messages (structured data plus the event as JSON) over UDP, TCP or TLS; TCP and TLS use octet counting (RFC 6587, RFC 5425).",
        properties: {
          host: { type: "string", example: "syslog.example.com" },
          port: { type: "integer", minimum: 1, maximum: 65535, description: "Defaults to 514 (udp, tcp) or 6514 (tls)" },
          protocol: { type: "string", enum: ["udp", "tcp", "tls"], default: "udp" },
          facility: { type: "integer", minimum: 0, maximum: 23, default: 13 },
          caPem: { type: ["string", "null"], description: "PEM CA that signs the receiver's certificate (tls only)" },
        },
        required: ["host"],
      },
      AuditSink: {
        type: "object",
        properties: {
          id: { type: "integer" },
          name: { type: "string" },
          type: { type: "string", enum: ["webhook", "syslog", "splunk_hec"] },
          enabled: { type: "boolean" },
          config: {
            oneOf: [
              { $ref: "#/components/schemas/WebhookSinkConfig" },
              { $ref: "#/components/schemas/SplunkHecSinkConfig" },
              { $ref: "#/components/schemas/SyslogSinkConfig" },
            ],
          },
          hasSecret: { type: "boolean", description: "A signing secret or HEC token is stored; it is never returned" },
          lastDeliveredId: { type: "integer", description: "Highest audit event id delivered" },
          pendingEvents: { type: "integer", description: "Audit events recorded after lastDeliveredId, waiting for this sink" },
          oldestPendingAt: {
            type: ["string", "null"],
            format: "date-time",
            description: "When the oldest event still waiting for this sink was recorded (its lag); null when nothing waits",
          },
          lastDeliveryAt: { type: ["string", "null"], format: "date-time" },
          lastError: { type: ["string", "null"] },
          lastErrorAt: { type: ["string", "null"], format: "date-time" },
          consecutiveFailures: { type: "integer" },
          nextAttemptAt: { type: ["string", "null"], format: "date-time", description: "Set while backing off after failures" },
          createdAt: { type: "string", format: "date-time" },
          updatedAt: { type: "string", format: "date-time" },
        },
        required: ["id", "name", "type", "enabled", "config", "hasSecret", "lastDeliveredId"],
      },
      AuditSinkInput: {
        type: "object",
        properties: {
          name: { type: "string", maxLength: 100 },
          type: { type: "string", enum: ["webhook", "syslog", "splunk_hec"] },
          enabled: { type: "boolean", default: true },
          config: {
            oneOf: [
              { $ref: "#/components/schemas/WebhookSinkConfig" },
              { $ref: "#/components/schemas/SplunkHecSinkConfig" },
              { $ref: "#/components/schemas/SyslogSinkConfig" },
            ],
          },
          secret: {
            type: "string",
            description: "Webhook signing secret (at least 16 characters) or Splunk HEC token; required for those types, not allowed for syslog",
          },
          backfill: { type: "boolean", default: false, description: "Also deliver every event already in the log" },
        },
        required: ["name", "type", "config"],
      },
      AuditSinkUpdate: {
        type: "object",
        properties: {
          name: { type: "string", maxLength: 100 },
          enabled: { type: "boolean" },
          config: { type: "object", description: "Merged into the stored config of the sink's type" },
          secret: { type: ["string", "null"], description: "Omit to keep the stored secret" },
        },
      },
      AuditSinkTestResult: {
        type: "object",
        properties: {
          ok: { type: "boolean" },
          error: { type: ["string", "null"] },
          durationMs: { type: "integer" },
        },
        required: ["ok", "error", "durationMs"],
      },
      BackupSchedule: {
        description: "Local wall-clock time in timeZone. A daily or weekly time skipped by a DST change runs right after the gap; a repeated one runs once.",
        oneOf: [
          {
            type: "object",
            properties: { kind: { type: "string", const: "hourly" }, minute: { type: "integer", minimum: 0, maximum: 59, default: 0 } },
            required: ["kind"],
            additionalProperties: false,
          },
          {
            type: "object",
            properties: { kind: { type: "string", const: "daily" }, time: { type: "string", pattern: "^([01]\\d|2[0-3]):[0-5]\\d$", example: "03:00" } },
            required: ["kind", "time"],
            additionalProperties: false,
          },
          {
            type: "object",
            properties: {
              kind: { type: "string", const: "weekly" },
              day: { type: "string", enum: ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"] },
              time: { type: "string", pattern: "^([01]\\d|2[0-3]):[0-5]\\d$", example: "03:00" },
            },
            required: ["kind", "day", "time"],
            additionalProperties: false,
          },
        ],
      },
      BackupDestination: {
        type: "object",
        properties: {
          id: { type: "integer" },
          name: { type: "string" },
          enabled: { type: "boolean" },
          endpoint: { type: "string", format: "uri", example: "https://s3.eu-central-1.amazonaws.com" },
          region: { type: "string", example: "eu-central-1" },
          bucket: { type: "string" },
          prefix: { type: "string", description: "Folder of the backup files, without leading or trailing slashes; empty for the bucket root" },
          pathStyle: { type: "boolean", description: "https://endpoint/bucket/key instead of https://bucket.endpoint/key" },
          accessKeyId: { type: "string" },
          hasSecretAccessKey: { type: "boolean", description: "The secret access key is stored (encrypted); it is never returned" },
          hasPassphrase: { type: "boolean", description: "The export passphrase is stored (encrypted); it is never returned" },
          schedule: { $ref: "#/components/schemas/BackupSchedule" },
          timeZone: { type: "string", example: "Europe/Rome" },
          retention: { type: "integer", minimum: 1, maximum: 1000, description: "Backup files to keep; older ones under the prefix are deleted" },
          nextRunAt: { type: ["string", "null"], format: "date-time", description: "Next scheduled attempt, or the retry time while backing off; null while disabled" },
          lastRunAt: { type: ["string", "null"], format: "date-time" },
          lastStatus: { type: ["string", "null"], enum: ["success", "failed", null] },
          lastError: { type: ["string", "null"] },
          lastSuccessAt: { type: ["string", "null"], format: "date-time" },
          consecutiveFailures: { type: "integer" },
          running: { type: "boolean", description: "A backup to this destination is in progress" },
          createdAt: { type: "string", format: "date-time" },
          updatedAt: { type: "string", format: "date-time" },
        },
        required: ["id", "name", "enabled", "endpoint", "region", "bucket", "prefix", "pathStyle", "accessKeyId", "hasSecretAccessKey", "hasPassphrase", "schedule", "timeZone", "retention", "consecutiveFailures", "running"],
      },
      BackupDestinationInput: {
        type: "object",
        additionalProperties: false,
        properties: {
          name: { type: "string", maxLength: 100 },
          enabled: { type: "boolean", default: true },
          endpoint: { type: "string", format: "uri", description: "http or https origin of the S3 API, without path, query or credentials" },
          region: { type: "string", default: "us-east-1", description: "auto for Cloudflare R2, the location (fsn1, nbg1, hel1) for Hetzner" },
          bucket: { type: "string", minLength: 3, maxLength: 63 },
          prefix: { type: "string", maxLength: 256, default: "" },
          pathStyle: { type: "boolean", default: false, description: "Required for IP-address or single-label endpoints (MinIO)" },
          accessKeyId: { type: "string", maxLength: 256 },
          secretAccessKey: { type: "string", writeOnly: true, maxLength: 1024 },
          passphrase: {
            type: "string",
            writeOnly: true,
            minLength: 12,
            maxLength: 1024,
            description: "Encrypts the secrets inside each backup file. Store it in a password manager: restoring on a new machine needs it.",
          },
          schedule: { $ref: "#/components/schemas/BackupSchedule" },
          timeZone: { type: "string", default: "UTC", description: "IANA time zone the schedule is read in" },
          retention: { type: "integer", minimum: 1, maximum: 1000, default: 30 },
        },
        required: ["name", "endpoint", "bucket", "accessKeyId", "secretAccessKey", "passphrase"],
      },
      BackupDestinationUpdate: {
        type: "object",
        additionalProperties: false,
        properties: {
          name: { type: "string", maxLength: 100 },
          enabled: { type: "boolean" },
          endpoint: { type: "string", format: "uri", description: "Changing it requires secretAccessKey" },
          region: { type: "string" },
          bucket: { type: "string" },
          prefix: { type: "string" },
          pathStyle: { type: "boolean" },
          accessKeyId: { type: "string" },
          secretAccessKey: { type: "string", writeOnly: true, description: "Omit or send an empty string to keep the stored one" },
          passphrase: { type: "string", writeOnly: true, minLength: 12, description: "Omit or send an empty string to keep the stored one" },
          schedule: { $ref: "#/components/schemas/BackupSchedule" },
          timeZone: { type: "string" },
          retention: { type: "integer", minimum: 1, maximum: 1000 },
        },
      },
      BackupRun: {
        type: "object",
        properties: {
          id: { type: "integer" },
          destinationId: { type: "integer" },
          destinationName: { type: ["string", "null"] },
          trigger: { type: "string", enum: ["schedule", "manual"] },
          status: { type: "string", enum: ["running", "success", "failed"] },
          startedAt: { type: "string", format: "date-time" },
          finishedAt: { type: ["string", "null"], format: "date-time" },
          objectKey: { type: ["string", "null"], example: "ingressi/ingressi-config-2026-10-02T03-00-00.123Z.json" },
          sizeBytes: { type: ["integer", "null"] },
          sha256: { type: ["string", "null"], description: "Hex SHA-256 of the uploaded file (also stored as x-amz-meta-sha256)" },
          prunedCount: { type: ["integer", "null"], description: "Older backup files deleted by retention" },
          error: { type: ["string", "null"] },
          warning: { type: ["string", "null"], description: "The upload worked but deleting older backups did not" },
        },
        required: ["id", "destinationId", "trigger", "status", "startedAt"],
      },
      BackupRunsResponse: {
        type: "object",
        properties: {
          runs: { type: "array", items: { $ref: "#/components/schemas/BackupRun" } },
          total: { type: "integer" },
          page: { type: "integer" },
          perPage: { type: "integer" },
        },
        required: ["runs", "total", "page", "perPage"],
      },
      BackupTestResult: {
        type: "object",
        properties: {
          ok: { type: "boolean" },
          error: { type: ["string", "null"] },
          failedStep: { type: ["string", "null"], enum: ["write", "read", "delete", null] },
          durationMs: { type: "integer" },
        },
        required: ["ok", "error", "failedStep", "durationMs"],
      },
      BackupObjectsListing: {
        type: "object",
        properties: {
          objects: {
            type: "array",
            items: {
              type: "object",
              properties: {
                key: { type: "string" },
                sizeBytes: { type: "integer" },
                lastModified: { type: ["string", "null"], format: "date-time" },
              },
              required: ["key", "sizeBytes", "lastModified"],
            },
          },
          complete: { type: "boolean", description: "False when the bucket listing was cut short" },
        },
        required: ["objects", "complete"],
      },
      BackupRestoreInput: {
        type: "object",
        additionalProperties: false,
        properties: {
          key: { type: "string", description: "A key from GET /api/v1/backup-destinations/{id}/objects" },
          passphrase: { type: "string", writeOnly: true, description: "Defaults to the destination's passphrase" },
        },
        required: ["key"],
      },
      BackupRestoreResult: {
        type: "object",
        properties: {
          ok: { type: "boolean" },
          key: { type: "string" },
          counts: { type: "object", additionalProperties: { type: "integer" } },
          warning: { type: ["string", "null"] },
          beforeSnapshotId: { type: ["integer", "null"], description: "History snapshot of the replaced configuration (when history is on)" },
        },
        required: ["ok", "key", "counts", "warning", "beforeSnapshotId"],
      },
    },
  },
};

export async function GET(request: NextRequest) {
  try {
    await requireApiPermission(request, "api_docs:read");
  } catch (error) {
    return apiErrorResponse(error);
  }
  // The API docs page shows the title: it follows the white-label product name.
  const title = `${brandName()} API`;
  return NextResponse.json(title === spec.info.title ? spec : { ...spec, info: { ...spec.info, title } }, {
    headers: {
      "Cache-Control": "private, max-age=3600",
    },
  });
}
