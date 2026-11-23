/**
 * MCP prompts: ready-made instructions a client can offer as slash commands.
 * They contain no data of their own; the text tells the model which tools to
 * call, so the user's permissions still decide what it can see.
 */

export type McpPromptArgument = {
  name: string;
  description: string;
  required?: boolean;
};

export type McpPrompt = {
  name: string;
  title: string;
  description: string;
  arguments: McpPromptArgument[];
  build: (args: Record<string, string>) => string;
};

function argument(args: Record<string, string>, name: string): string {
  return (args[name] ?? "").trim();
}

export const MCP_PROMPTS: readonly McpPrompt[] = [
  {
    name: "review_proxy_host",
    title: "Review a proxy host",
    description: "Check one proxy host's configuration and traffic for obvious problems.",
    arguments: [{ name: "id", description: "The proxy host id.", required: true }],
    build: (args) => {
      const id = argument(args, "id");
      return [
        `Review proxy host ${id}.`,
        `1. Call get_proxy_host with id ${id} and describe routing, TLS, access control (access list, mTLS, forward auth), WAF and rate limiting.`,
        `2. Call list_certificates with search set to one of its domains and report the expiry and renewal state.`,
        `3. Call query_traffic with the range "24h" and groupBy "status", then list_security_events with the host's main domain.`,
        "4. Point out anything that looks wrong or risky (no HTTPS redirect, HTTP upstream on a public host, no access list on an administrative path, expiring certificate, 5xx or blocked traffic), with the concrete change you would make.",
      ].join("\n");
    },
  },
  {
    name: "triage_security_events",
    title: "Triage security events",
    description: "Summarize what was blocked recently and what it means for one host or the whole instance.",
    arguments: [
      { name: "range", description: "1h, 6h, 24h, 7d or 30d (default 24h)." },
      { name: "host", description: "A host name; all hosts when omitted." },
    ],
    build: (args) => {
      const range = argument(args, "range") || "24h";
      const host = argument(args, "host");
      return [
        `Triage security events for the last ${range}${host ? ` on ${host}` : ""}.`,
        `1. Call list_security_events with range "${range}"${host ? ` and host "${host}"` : ""}, and raise limit to 200 if there are many.`,
        "2. Group the events by kind, rule, source IP and country, and say how many requests were blocked versus only observed.",
        host
          ? `3. Call get_proxy_host after finding the host's id in list_proxy_hosts with search "${host}", and check whether the WAF, access list and rate limiting are what you would expect for this traffic.`
          : "3. Call list_proxy_hosts and identify the hosts most affected.",
        "4. Recommend concrete actions (a WAF rule exclusion if legitimate traffic is blocked, a rate limit, an access list, or no change) and call out anything that needs a human to verify first.",
      ].join("\n");
    },
  },
  {
    name: "onboard_service",
    title: "Onboard a service",
    description: "Add a reverse proxy host for a domain and upstream, checking what already exists first.",
    arguments: [
      { name: "domain", description: "The public domain name.", required: true },
      { name: "upstream", description: "The upstream URL, e.g. http://app:8080.", required: true },
    ],
    build: (args) => {
      const domain = argument(args, "domain");
      const upstream = argument(args, "upstream");
      return [
        `Expose ${upstream} at https://${domain}.`,
        `1. Call search with query "${domain}" and list_proxy_hosts with search "${domain}" to check that the name is free and see whether a certificate or access list is already used for similar hosts.`,
        "2. Call list_access_lists: propose one only if the service is administrative or internal.",
        "3. Call create_proxy_host with name, domains: [\"" + domain + "\"], upstreams: [\"" + upstream + "\"], and sslForced: true. Leave certificateId out unless a wildcard certificate already covers the name.",
        "4. If the answer is a change request, say so instead of retrying. Otherwise call list_certificates with search \"" + domain + "\" and report when the certificate will be ready.",
      ].join("\n");
    },
  },
  {
    name: "certificate_expiry_check",
    title: "Check certificate expiry",
    description: "List certificates that expire soon and the hosts they cover.",
    arguments: [],
    build: () => [
      "Check certificate expiry.",
      "1. Call list_certificates with expiringWithinDays 30 and limit 200.",
      "2. For each row, report the name, domains, days left, renewal state and the hosts that use it.",
      "3. Say which ones renew automatically and which need a person (imported certificates), and flag anything expired.",
    ].join("\n"),
  },
];

export const MCP_PROMPT_BY_NAME: ReadonlyMap<string, McpPrompt> = new Map(MCP_PROMPTS.map((prompt) => [prompt.name, prompt]));

export function listPrompts() {
  return MCP_PROMPTS.map(({ name, title, description, arguments: promptArguments }) => ({
    name,
    title,
    description,
    arguments: promptArguments,
  }));
}

export type McpPromptResult =
  | { ok: true; description: string; messages: Array<{ role: "user"; content: { type: "text"; text: string } }> }
  | { ok: false; error: string };

/** prompts/get: the prompt with the user's arguments filled in. */
export function getPrompt(name: string, args: Record<string, string>): McpPromptResult | null {
  const prompt = MCP_PROMPT_BY_NAME.get(name);
  if (!prompt) return null;
  for (const definition of prompt.arguments) {
    if (definition.required && !argument(args, definition.name)) {
      return { ok: false, error: `Missing required argument: ${definition.name}` };
    }
  }
  return {
    ok: true,
    description: prompt.description,
    messages: [
      {
        role: "user",
        content: { type: "text", text: prompt.build(args) },
      },
    ],
  };
}
