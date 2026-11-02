// SPDX-License-Identifier: Elastic-2.0
/**
 * Verifying a SAML response posted to the assertion consumer service.
 *
 * Signature verification is @node-saml/node-saml's (on xml-crypto, with the
 * signing certificates pinned to the provider's: certificates in the
 * message's KeyInfo are never trusted). Everything that decides whether the
 * signed assertion may sign someone in is checked here as well, on the
 * signed bytes only, whether or not the library checks it too:
 *
 *  - before the signature is looked at, the message's structure: one
 *    Response, exactly one Assertion anywhere in it (a direct child of the
 *    Response), no encrypted assertion, signatures only directly on the
 *    Response or the Assertion and at most one each, no duplicate ID
 *    attributes, no DOCTYPE. This refuses the XML signature wrapping
 *    variants, which all add a second Assertion, move the signed one, or
 *    reuse an ID;
 *  - the algorithms of every signature, read from the XML: RSA with SHA-256
 *    or SHA-512 for the signature and SHA-256 or SHA-512 for every digest.
 *    SHA-1 and HMAC are refused whatever the identity provider chose;
 *  - SP-initiated only: the Response must answer the AuthnRequest this
 *    browser started (InResponseTo), and so must the bearer
 *    SubjectConfirmationData inside the signed assertion, whose Recipient
 *    must be this provider's ACS URL and whose NotOnOrAfter must be present
 *    and not passed. A response without InResponseTo (IdP-initiated) is
 *    refused;
 *  - issuer (Response and Assertion), Destination (required when the
 *    Response is signed), audience, Conditions, IssueInstant (not before the
 *    sign-in started) and SessionNotOnOrAfter, each with a clock skew of
 *    CLOCK_SKEW_MS.
 *
 * Replay protection (the assertion ID used once) and binding the response
 * to the browser are the caller's (plugin.ts, requests.ts). Nothing here
 * reads the database.
 */
import { SAML, SamlStatusError, ValidateInResponseTo, type CacheProvider } from "@node-saml/node-saml";
import {
  ALLOWED_DIGEST_ALGORITHMS,
  ALLOWED_SIGNATURE_ALGORITHMS,
  ALLOWED_TRANSFORMS,
  CLOCK_SKEW_MS,
  CONFIRMATION_BEARER,
  LIMITS,
  REQUEST_TTL_MS,
  STATUS_SUCCESS,
  XML_NS,
} from "./constants";
import { serviceProviderUrls } from "./store";
import type { SamlAssertionIdentity, SamlProviderConfig } from "./types";
import { XmlInputError, allElements, attribute, childrenNamed, onlyChild, parseXml, simpleText } from "./xml";

export type SamlFailureReason =
  | "malformed"
  | "unsupported"
  | "status"
  | "idp_initiated"
  | "wrapping"
  | "algorithm"
  | "signature"
  | "issuer"
  | "destination"
  | "in_response_to"
  | "recipient"
  | "audience"
  | "expired"
  | "not_yet_valid"
  | "subject";

/** A refused response; `message` is for the audit log and the server log, never for the browser. */
export class SamlResponseError extends Error {
  constructor(readonly reason: SamlFailureReason, message: string) {
    super(message);
    this.name = "SamlResponseError";
  }
}

function refuse(reason: SamlFailureReason, message: string): never {
  throw new SamlResponseError(reason, message);
}

export type ExpectedResponse = {
  provider: Pick<SamlProviderConfig, "id" | "idpEntityId" | "idpCertificates">;
  /** The ID of the AuthnRequest this browser started. */
  requestId: string;
  /** When that sign-in started (ms). */
  requestCreatedAt: number;
  now?: number;
};

const ID_ATTRIBUTES = ["ID", "Id", "id"] as const;

/** Decodes the posted SAMLResponse (base64), refusing anything else. */
export function decodeSamlResponse(posted: string): { base64: string; xml: string } {
  const base64 = posted.replace(/[\r\n\t ]+/g, "");
  if (!base64 || base64.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(base64)) {
    refuse("malformed", "SAMLResponse is not base64");
  }
  const bytes = Buffer.from(base64, "base64");
  if (bytes.length > LIMITS.responseXml) refuse("malformed", "the response is too large");
  const xml = bytes.toString("utf8");
  if (Buffer.byteLength(xml, "utf8") !== bytes.length) refuse("malformed", "the response is not UTF-8");
  return { base64, xml };
}

function parseTime(value: string | null, what: string): number | null {
  if (value === null) return null;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/.test(value)) {
    refuse("malformed", `${what} is not a valid time`);
  }
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) refuse("malformed", `${what} is not a valid time`);
  return ms;
}

function textValue(element: Element | null): string | null {
  if (!element) return null;
  const text = simpleText(element);
  return text === null ? null : text.trim();
}

/** Every check that needs no signature: structure, algorithms, status, the request it answers. */
function checkStructure(doc: Document, expected: ExpectedResponse, acsUrl: string): Element {
  const root = doc.documentElement;
  if (root.namespaceURI !== XML_NS.protocol || root.localName !== "Response") refuse("malformed", "the message is not a SAML 2.0 Response");
  if (attribute(root, "Version") !== "2.0") refuse("malformed", "the Response is not SAML 2.0");

  const status = onlyChild(root, XML_NS.protocol, "Status", "the Response");
  const statusCode = status ? onlyChild(status, XML_NS.protocol, "StatusCode", "Status") : null;
  const statusValue = statusCode ? attribute(statusCode, "Value") : null;
  if (statusValue !== STATUS_SUCCESS) {
    const nested = statusCode ? childrenNamed(statusCode, XML_NS.protocol, "StatusCode")[0] : undefined;
    const detail = [statusValue, nested ? attribute(nested, "Value") : null].filter(Boolean).join(" / ") || "none";
    refuse("status", `the identity provider did not sign the user in (status ${detail})`);
  }

  const elements = allElements(root);
  if (elements.some((element) => element.localName === "EncryptedAssertion" || element.localName === "EncryptedID")) {
    refuse("unsupported", "encrypted assertions and encrypted NameIDs are not supported; turn assertion encryption off at the identity provider");
  }
  const assertions = elements.filter((element) => element.localName === "Assertion");
  if (assertions.length === 0) refuse("malformed", "the Response has no Assertion");
  if (assertions.length > 1) refuse("wrapping", "the Response has more than one Assertion element");
  const assertion = assertions[0];
  if (assertion.parentNode !== root || assertion.namespaceURI !== XML_NS.assertion) {
    refuse("wrapping", "the Assertion is not a direct child of the Response");
  }

  const signatures = elements.filter((element) => element.localName === "Signature");
  const signedParents = new Set<Node>();
  for (const signature of signatures) {
    if (signature.namespaceURI !== XML_NS.dsig) refuse("wrapping", "a Signature element is not an XML signature");
    const parent = signature.parentNode;
    if (parent !== root && parent !== assertion) refuse("wrapping", "a signature is neither on the Response nor on the Assertion");
    if (signedParents.has(parent)) refuse("wrapping", "an element carries more than one signature");
    signedParents.add(parent);
    for (const inner of allElements(signature)) {
      for (let child = inner.firstChild; child; child = child.nextSibling) {
        // Comments (CVE-2025-29775) and processing instructions have no place in a signature.
        if (child.nodeType === 7 || child.nodeType === 8) refuse("wrapping", "a signature contains a comment or processing instruction");
      }
    }
  }
  if (signatures.length === 0) refuse("signature", "the response is not signed");

  for (const element of elements) {
    const algorithm = attribute(element, "Algorithm");
    switch (element.localName) {
      case "SignatureMethod":
        if (!algorithm || !ALLOWED_SIGNATURE_ALGORITHMS.has(algorithm)) {
          refuse("algorithm", `signature algorithm ${algorithm ?? "(none)"} is not accepted; use RSA-SHA256 or RSA-SHA512`);
        }
        break;
      case "DigestMethod":
        if (!algorithm || !ALLOWED_DIGEST_ALGORITHMS.has(algorithm)) {
          refuse("algorithm", `digest algorithm ${algorithm ?? "(none)"} is not accepted; use SHA-256 or SHA-512`);
        }
        break;
      case "CanonicalizationMethod":
      case "Transform":
        if (!algorithm || !ALLOWED_TRANSFORMS.has(algorithm)) refuse("algorithm", `transform ${algorithm ?? "(none)"} is not accepted`);
        break;
    }
  }

  const ids = new Set<string>();
  for (const element of elements) {
    for (const name of ID_ATTRIBUTES) {
      const value = attribute(element, name);
      if (value === null) continue;
      if (ids.has(value)) refuse("wrapping", "two elements carry the same ID");
      ids.add(value);
    }
  }

  const inResponseTo = attribute(root, "InResponseTo");
  if (!inResponseTo) refuse("idp_initiated", "IdP-initiated sign-in is not supported: the Response answers no request");
  if (inResponseTo !== expected.requestId) refuse("in_response_to", "the Response answers another sign-in (InResponseTo)");

  const destination = attribute(root, "Destination");
  if (destination !== null && destination !== acsUrl) refuse("destination", "the Response is addressed to another URL (Destination)");
  if (destination === null && signedParents.has(root)) refuse("destination", "a signed Response must name its Destination");

  const responseIssuer = onlyChild(root, XML_NS.assertion, "Issuer", "the Response");
  if (responseIssuer && textValue(responseIssuer) !== expected.provider.idpEntityId) {
    refuse("issuer", "the Response comes from another identity provider (Issuer)");
  }
  return assertion;
}

/** Only the AuthnRequest of this sign-in is outstanding; consuming it is the caller's job. */
function oneRequestCache(requestId: string, createdAt: number): CacheProvider {
  return {
    saveAsync: async () => null,
    getAsync: async (key) => (key === requestId ? new Date(createdAt).toISOString() : null),
    removeAsync: async () => null,
  };
}

function libraryReason(error: unknown): { reason: SamlFailureReason; message: string } {
  if (error instanceof SamlStatusError) return { reason: "status", message: error.message };
  const message = error instanceof Error ? error.message : String(error);
  // node-saml 5.2 checks the Assertion's Issuer itself and says "Unknown SAML issuer. Expected: ...".
  if (/^Unknown SAML issuer/.test(message)) return { reason: "issuer", message };
  if (/audience/i.test(message)) return { reason: "audience", message };
  if (/not yet valid/i.test(message)) return { reason: "not_yet_valid", message };
  // "No valid subject confirmation": none whose time window holds; a missing NotOnOrAfter cannot be parsed.
  if (/expired|too old|subject confirmation|NotOnOrAfter/i.test(message)) return { reason: "expired", message };
  if (/InResponseTo/i.test(message)) return { reason: "in_response_to", message };
  if (/signature|signed|reference|transform/i.test(message)) return { reason: "signature", message };
  return { reason: "malformed", message };
}

async function verifySignature(base64: string, expected: ExpectedResponse, sp: { entityId: string; acsUrl: string }): Promise<string> {
  const saml = new SAML({
    callbackUrl: sp.acsUrl,
    issuer: sp.entityId,
    audience: sp.entityId,
    idpCert: expected.provider.idpCertificates,
    idpIssuer: expected.provider.idpEntityId,
    // Either signature covers the assertion: the Response's (which encloses
    // it) or the Assertion's own. Unsigned messages are refused above already.
    wantAuthnResponseSigned: false,
    wantAssertionsSigned: false,
    acceptedClockSkewMs: CLOCK_SKEW_MS,
    validateInResponseTo: ValidateInResponseTo.always,
    requestIdExpirationPeriodMs: REQUEST_TTL_MS,
    cacheProvider: oneRequestCache(expected.requestId, expected.requestCreatedAt),
  });
  let profile;
  try {
    ({ profile } = await saml.validatePostResponseAsync({ SAMLResponse: base64 }));
  } catch (error) {
    const { reason, message } = libraryReason(error);
    refuse(reason, message);
  }
  // The bytes the signature covers (xml-crypto's signed references), never the posted ones.
  const signed = profile?.getAssertionXml?.();
  if (!signed) refuse("malformed", "the response holds no signed assertion");
  return signed;
}

type Confirmation = { notOnOrAfter: number };

/** Finds a bearer SubjectConfirmation of this sign-in, or refuses with the most telling reason. */
function checkSubjectConfirmation(subject: Element, expected: ExpectedResponse, acsUrl: string, now: number): Confirmation {
  const problems: Array<{ reason: SamlFailureReason; message: string }> = [];
  for (const confirmation of childrenNamed(subject, XML_NS.assertion, "SubjectConfirmation")) {
    if (attribute(confirmation, "Method") !== CONFIRMATION_BEARER) continue;
    const data = onlyChild(confirmation, XML_NS.assertion, "SubjectConfirmationData", "SubjectConfirmation");
    if (!data) {
      problems.push({ reason: "subject", message: "the bearer SubjectConfirmation has no SubjectConfirmationData" });
      continue;
    }
    const inResponseTo = attribute(data, "InResponseTo");
    if (inResponseTo !== expected.requestId) {
      problems.push({
        reason: inResponseTo ? "in_response_to" : "idp_initiated",
        message: inResponseTo
          ? "the assertion answers another sign-in (SubjectConfirmationData InResponseTo)"
          : "the assertion answers no request (SubjectConfirmationData has no InResponseTo)",
      });
      continue;
    }
    if (attribute(data, "Recipient") !== acsUrl) {
      problems.push({ reason: "recipient", message: "the assertion is meant for another URL (SubjectConfirmationData Recipient)" });
      continue;
    }
    const notOnOrAfter = parseTime(attribute(data, "NotOnOrAfter"), "SubjectConfirmationData NotOnOrAfter");
    if (notOnOrAfter === null) {
      problems.push({ reason: "expired", message: "the bearer SubjectConfirmationData has no NotOnOrAfter" });
      continue;
    }
    if (now - CLOCK_SKEW_MS >= notOnOrAfter) {
      problems.push({ reason: "expired", message: "the assertion has expired (SubjectConfirmationData NotOnOrAfter)" });
      continue;
    }
    const notBefore = parseTime(attribute(data, "NotBefore"), "SubjectConfirmationData NotBefore");
    if (notBefore !== null && now + CLOCK_SKEW_MS < notBefore) {
      problems.push({ reason: "not_yet_valid", message: "the assertion is not valid yet (SubjectConfirmationData NotBefore)" });
      continue;
    }
    return { notOnOrAfter };
  }
  const order: SamlFailureReason[] = ["in_response_to", "idp_initiated", "recipient", "expired", "not_yet_valid", "subject"];
  problems.sort((a, b) => order.indexOf(a.reason) - order.indexOf(b.reason));
  return refuse(problems[0]?.reason ?? "subject", problems[0]?.message ?? "the assertion has no bearer SubjectConfirmation");
}

function readAttributes(assertion: Element): Map<string, string[]> {
  const attributes = new Map<string, string[]>();
  for (const statement of childrenNamed(assertion, XML_NS.assertion, "AttributeStatement")) {
    for (const element of childrenNamed(statement, XML_NS.assertion, "Attribute")) {
      const name = attribute(element, "Name");
      if (!name) continue;
      if (!attributes.has(name) && attributes.size >= LIMITS.attributes) refuse("malformed", "the assertion has too many attributes");
      const values = attributes.get(name) ?? [];
      for (const valueElement of childrenNamed(element, XML_NS.assertion, "AttributeValue")) {
        // Only simple values: a value with element children is never read as text.
        const text = simpleText(valueElement);
        if (text === null || text.length === 0) continue;
        if (values.length >= LIMITS.attributeValues) refuse("malformed", `attribute ${name.slice(0, 80)} has too many values`);
        values.push(text);
      }
      attributes.set(name, values);
    }
  }
  return attributes;
}

/** The checks on the signed assertion. */
function checkAssertion(
  xml: string,
  expectedId: string | null,
  expected: ExpectedResponse,
  sp: { entityId: string; acsUrl: string },
  now: number
): SamlAssertionIdentity {
  let doc: Document;
  try {
    doc = parseXml(xml, "The signed assertion");
  } catch (error) {
    refuse("malformed", error instanceof Error ? error.message : "the signed assertion cannot be read");
  }
  const assertion = doc.documentElement;
  if (assertion.namespaceURI !== XML_NS.assertion || assertion.localName !== "Assertion") {
    refuse("wrapping", "the signed content is not an Assertion");
  }
  const assertionId = attribute(assertion, "ID");
  if (!assertionId || assertionId.length > 256) refuse("malformed", "the assertion has no usable ID");
  if (assertionId !== expectedId) refuse("wrapping", "the signed assertion is not the one in the Response");
  if (attribute(assertion, "Version") !== "2.0") refuse("malformed", "the assertion is not SAML 2.0");

  const issuer = textValue(onlyChild(assertion, XML_NS.assertion, "Issuer", "the assertion"));
  if (issuer !== expected.provider.idpEntityId) refuse("issuer", "the assertion comes from another identity provider (Issuer)");

  const issueInstant = parseTime(attribute(assertion, "IssueInstant"), "IssueInstant");
  if (issueInstant === null) refuse("malformed", "the assertion has no IssueInstant");
  if (issueInstant > now + CLOCK_SKEW_MS) refuse("not_yet_valid", "the assertion was issued in the future (IssueInstant)");
  if (issueInstant < expected.requestCreatedAt - CLOCK_SKEW_MS) refuse("expired", "the assertion was issued before this sign-in started (IssueInstant)");

  const subject = onlyChild(assertion, XML_NS.assertion, "Subject", "the assertion");
  if (!subject) refuse("subject", "the assertion has no Subject");
  const confirmation = checkSubjectConfirmation(subject, expected, sp.acsUrl, now);
  const nameIdElement = onlyChild(subject, XML_NS.assertion, "NameID", "the Subject");
  const nameId = nameIdElement ? textValue(nameIdElement) : null;
  const nameIdFormat = nameIdElement ? attribute(nameIdElement, "Format") : null;

  const conditions = onlyChild(assertion, XML_NS.assertion, "Conditions", "the assertion");
  if (!conditions) refuse("audience", "the assertion has no Conditions, so no audience");
  const notBefore = parseTime(attribute(conditions, "NotBefore"), "Conditions NotBefore");
  if (notBefore !== null && now + CLOCK_SKEW_MS < notBefore) refuse("not_yet_valid", "the assertion is not valid yet (Conditions NotBefore)");
  const notOnOrAfter = parseTime(attribute(conditions, "NotOnOrAfter"), "Conditions NotOnOrAfter");
  if (notOnOrAfter !== null && now - CLOCK_SKEW_MS >= notOnOrAfter) refuse("expired", "the assertion has expired (Conditions NotOnOrAfter)");
  const restrictions = childrenNamed(conditions, XML_NS.assertion, "AudienceRestriction");
  if (restrictions.length === 0) refuse("audience", "the assertion has no AudienceRestriction");
  for (const restriction of restrictions) {
    const audiences = childrenNamed(restriction, XML_NS.assertion, "Audience").map((element) => textValue(element));
    if (!audiences.includes(sp.entityId)) refuse("audience", "the assertion is meant for another service provider (Audience)");
  }

  const statements = childrenNamed(assertion, XML_NS.assertion, "AuthnStatement");
  if (statements.length === 0) refuse("subject", "the assertion has no AuthnStatement");
  for (const statement of statements) {
    const sessionEnd = parseTime(attribute(statement, "SessionNotOnOrAfter"), "SessionNotOnOrAfter");
    if (sessionEnd !== null && now - CLOCK_SKEW_MS >= sessionEnd) refuse("expired", "the identity provider session has ended (SessionNotOnOrAfter)");
  }

  return {
    assertionId,
    issuer,
    nameId: nameId || null,
    nameIdFormat,
    attributes: readAttributes(assertion),
    replayUntil: Math.max(confirmation.notOnOrAfter, notOnOrAfter ?? 0) + CLOCK_SKEW_MS,
  };
}

/**
 * Verifies a posted SAMLResponse for `expected` and returns the identity
 * the signed assertion carries. Throws SamlResponseError otherwise.
 */
export async function verifySamlResponse(posted: string, expected: ExpectedResponse): Promise<SamlAssertionIdentity> {
  const now = expected.now ?? Date.now();
  if (expected.provider.idpCertificates.length === 0) refuse("signature", "the provider has no signing certificate");
  const sp = serviceProviderUrls(expected.provider.id);
  const { base64, xml } = decodeSamlResponse(posted);
  let doc: Document;
  try {
    doc = parseXml(xml, "The response");
  } catch (error) {
    refuse("malformed", error instanceof XmlInputError ? error.message : "the response cannot be read");
  }
  const assertion = checkStructure(doc, expected, sp.acsUrl);
  const signedAssertion = await verifySignature(base64, expected, sp);
  return checkAssertion(signedAssertion, attribute(assertion, "ID"), expected, sp, now);
}
