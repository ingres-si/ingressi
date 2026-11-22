import { redirect } from "next/navigation";
import type { ReactNode } from "react";
import type { Metadata } from "next";
import { ArrowRight, ShieldCheck, TriangleAlert } from "lucide-react";
import { getSessionAccess, requireUser } from "@/src/lib/auth";
import { getUserById } from "@/src/lib/models/user";
import {
  authorizationErrorRedirect,
  buildRedirect,
  clientDisplay,
  parseAuthorizationRequest,
} from "@/src/lib/mcp/authorize";
import { getMcpSettings } from "@/src/lib/mcp/config";
import { getClient } from "@/src/lib/mcp/oauth";
import { describeScopes, scopeString } from "@/src/lib/mcp/scopes";
import { BRAND_NAME } from "@/src/lib/brand";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Authorize MCP client",
  robots: { index: false, follow: false },
};

type SearchParams = Record<string, string | string[] | undefined>;

function paramsFrom(searchParams: SearchParams): URLSearchParams {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(searchParams)) {
    if (typeof value === "string") params.set(key, value);
    else if (Array.isArray(value) && typeof value[0] === "string") params.set(key, value[0]);
  }
  return params;
}

function Shell({ children }: { children: ReactNode }) {
  return (
    <main className="flex min-h-svh items-center justify-center bg-muted/40 px-4 py-10">
      <div className="w-full max-w-xl rounded-xl border bg-card p-6 shadow-sm sm:p-8">{children}</div>
    </main>
  );
}

function Problem({ title, detail }: { title: string; detail: string }) {
  return (
    <Shell>
      <div className="flex items-start gap-3">
        <TriangleAlert className="mt-0.5 size-5 shrink-0 text-amber-500" aria-hidden="true" />
        <div>
          <h1 className="text-lg font-semibold">{title}</h1>
          <p className="mt-2 text-sm text-muted-foreground">{detail}</p>
          <p className="mt-4 text-sm text-muted-foreground">
            Nothing was shared and no access was granted. Close this window and try connecting again from your MCP client.
          </p>
        </div>
      </div>
    </Shell>
  );
}

export default async function AuthorizePage({
  searchParams,
}: {
  searchParams?: Promise<SearchParams>;
} = {}) {
  const settings = await getMcpSettings();
  if (!settings.enabled) {
    return <Problem title="The MCP server is off" detail="An administrator disabled the MCP server on this instance." />;
  }

  const session = await requireUser();
  const access = await getSessionAccess(session);
  const user = await getUserById(Number(session.user.id));
  if (!user || user.status !== "active") {
    return <Problem title="Account unavailable" detail="This account is not active." />;
  }

  const raw = (await searchParams) ?? {};
  const parsed = await parseAuthorizationRequest(paramsFrom(raw), access);
  if (!parsed.ok) {
    if (parsed.fatal) {
      return <Problem title="This authorization request is not valid" detail={parsed.description} />;
    }
    redirect(authorizationErrorRedirect(parsed));
  }
  const request = parsed.request;
  const client = await getClient(request.clientId);
  if (!client || client.revokedAt) {
    return <Problem title="Unknown client" detail="This client is no longer registered." />;
  }
  const display = clientDisplay(client);

  // Every authorization request shows the consent screen, even for a client
  // approved before. Issuing a code straight from a GET would let another site
  // make the browser fetch an authorization URL and collect the code from the
  // client's registered redirect URI, without the user seeing anything.
  // Refresh tokens make repeat prompts rare in practice; the POST below
  // re-validates every field.

  // prompt=none asks for no interaction; this server always asks, so it can
  // only answer that interaction is required.
  if (request.prompt.includes("none")) {
    redirect(
      buildRedirect(request.redirectUri, {
        state: request.state,
        error: "consent_required",
        errorDescription: "The user has to approve this request",
      })
    );
  }

  const scopes = describeScopes(request.scopes);
  let redirectHost = request.redirectUri;
  let loopback = false;
  try {
    const url = new URL(request.redirectUri);
    redirectHost = `${url.host}${url.pathname}`;
    loopback = ["localhost", "127.0.0.1", "[::1]", "::1"].includes(url.hostname.toLowerCase());
  } catch {
    // Already validated; keep the full URI as the label.
  }

  return (
    <Shell>
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <ShieldCheck className="size-4" aria-hidden="true" />
        {BRAND_NAME}
      </div>
      <h1 className="mt-3 text-xl font-semibold">Authorize {display.name}?</h1>
      <p className="mt-2 text-sm text-muted-foreground">
        <span className="font-medium text-foreground">{display.name}</span> wants to connect to your {BRAND_NAME} instance as{" "}
        <span className="font-medium text-foreground">{user.email}</span>.
      </p>

      <div className="mt-5 rounded-lg border bg-muted/30 p-4">
        <p className="text-sm font-medium">It will be able to:</p>
        <ul className="mt-2 space-y-2">
          {scopes.map((scope) => (
            <li key={scope.scope} className="text-sm">
              <span className="font-medium">{scope.title}</span>
              <span className="block text-xs text-muted-foreground">{scope.description}</span>
            </li>
          ))}
        </ul>
        <p className="mt-3 text-xs text-muted-foreground">
          Access follows your role at the time of each action: permissions you lose stop working for this client too. An
          administrator can disconnect it at any time under Settings → MCP server.
        </p>
      </div>

      <p className="mt-4 text-xs text-muted-foreground">
        It will return to <span className="font-mono break-all">{redirectHost}</span>
      </p>
      {loopback && (
        <p className="mt-2 flex items-start gap-2 text-xs text-amber-600 dark:text-amber-500">
          <TriangleAlert className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
          This client runs on your own computer. Allow it only if you started the connection yourself.
        </p>
      )}

      <form method="POST" action="/api/oauth/authorize" className="mt-6 flex flex-col gap-2 sm:flex-row">
        <input type="hidden" name="client_id" value={request.clientId} />
        <input type="hidden" name="redirect_uri" value={request.redirectUri} />
        <input type="hidden" name="response_type" value="code" />
        <input type="hidden" name="code_challenge" value={request.codeChallenge} />
        <input type="hidden" name="code_challenge_method" value="S256" />
        <input type="hidden" name="scope" value={scopeString(request.scopes)} />
        <input type="hidden" name="resource" value={request.resource} />
        {request.state !== null && <input type="hidden" name="state" value={request.state} />}
        {request.prompt.length > 0 && <input type="hidden" name="prompt" value={request.prompt.join(" ")} />}
        <button
          type="submit"
          name="decision"
          value="allow"
          className="inline-flex h-9 flex-1 items-center justify-center gap-2 rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground shadow-xs transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          Authorize
          <ArrowRight className="size-4" aria-hidden="true" />
        </button>
        <button
          type="submit"
          name="decision"
          value="deny"
          className="inline-flex h-9 flex-1 items-center justify-center rounded-md border bg-background px-4 text-sm font-medium shadow-xs transition-colors hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          Cancel
        </button>
      </form>
    </Shell>
  );
}
