"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Check, Copy, ExternalLink, Plug, ShieldCheck, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "@/components/ui/PageHeader";
import { SectionCard } from "@/components/ui/SectionCard";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState } from "@/components/ui/EmptyState";
import { jsonInit, readError } from "@/src/lib/request-json";
import { formatDateTime } from "@/src/lib/date-format";
import type { McpSettings } from "@/src/lib/mcp/config";
import type { McpClientSummary, McpConnection } from "@/src/lib/mcp/oauth";

export type McpPageClientProps = {
  initialSettings: McpSettings;
  canWrite: boolean;
  clients: McpClientSummary[];
  connections: McpConnection[];
  endpoint: string;
  protectedResourceMetadataUrl: string;
  authorizationServerMetadataUrl: string;
  scopes: string[];
  protocolVersion: string;
  tools: Array<{ name: string; title: string; permission: string | null }>;
};

function CopyField({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      toast.success(`${label} copied`);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      toast.error("Could not copy to the clipboard");
    }
  };
  return (
    <div className="flex items-center gap-2">
      <code className="min-w-0 flex-1 truncate rounded-md border bg-muted/40 px-2.5 py-1.5 font-mono text-xs">{value}</code>
      <Button type="button" variant="outline" size="sm" onClick={copy} aria-label={`Copy ${label}`}>
        {copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
        <span className="hidden sm:inline">{copied ? "Copied" : "Copy"}</span>
      </Button>
    </div>
  );
}

function ToggleRow({
  id,
  label,
  description,
  checked,
  disabled,
  onChange,
}: {
  id: string;
  label: string;
  description: string;
  checked: boolean;
  disabled: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <div className="flex items-start justify-between gap-4 py-3 first:pt-0 last:pb-0">
      <div>
        <label htmlFor={id} className="text-sm font-medium">
          {label}
        </label>
        <p className="mt-0.5 text-xs text-muted-foreground">{description}</p>
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onChange} disabled={disabled} />
    </div>
  );
}

function when(value: string | null): string {
  return value ? formatDateTime(value) : "Never";
}

/** Settings → MCP server. */
export default function McpPageClient(props: McpPageClientProps) {
  const router = useRouter();
  const [settings, setSettings] = useState(props.initialSettings);
  const [saving, startSaving] = useTransition();
  const [revoking, setRevoking] = useState<string | null>(null);

  const save = (next: McpSettings) => {
    const previous = settings;
    setSettings(next);
    startSaving(async () => {
      try {
        const response = await fetch("/api/v1/mcp/settings", jsonInit("PUT", next));
        if (!response.ok) throw new Error(await readError(response));
        setSettings(next);
        toast.success(next.enabled ? "MCP server enabled" : "MCP server disabled");
        router.refresh();
      } catch (error) {
        setSettings(previous);
        toast.error(error instanceof Error ? error.message : "Could not save the settings");
      }
    });
  };

  const revoke = async (kind: "connections" | "clients", id: string, label: string) => {
    if (!window.confirm(`Disconnect ${label}? Its tokens stop working immediately.`)) return;
    setRevoking(`${kind}:${id}`);
    try {
      const response = await fetch(`/api/v1/mcp/${kind}/${encodeURIComponent(id)}`, { method: "DELETE" });
      if (!response.ok) throw new Error(await readError(response));
      toast.success(`${label} disconnected`);
      router.refresh();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not revoke it");
    } finally {
      setRevoking(null);
    }
  };

  const disabled = !props.canWrite || saving;

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        className="mb-0"
        breadcrumb={["Settings", "MCP server"]}
        title="MCP server"
        description="Let AI clients such as Claude, ChatGPT and Cursor manage this instance through the Model Context Protocol, with OAuth sign-in and the permissions of the account that approves them."
        actions={
          <Button asChild variant="outline">
            <a href="https://github.com/ingres-si/ingressi/blob/develop/documentation/mcp.md" target="_blank" rel="noopener">
              <ExternalLink aria-hidden="true" />
              Documentation
            </a>
          </Button>
        }
      />

      <SectionCard
        title="Connection"
        description="Give this URL to an MCP client. It discovers the authorization server, registers itself and asks you to approve its scopes."
        padded
      >
        <div className="flex flex-col gap-3">
          <CopyField value={props.endpoint} label="MCP endpoint" />
          <details className="text-sm">
            <summary className="cursor-pointer text-muted-foreground hover:text-foreground">Discovery documents</summary>
            <div className="mt-3 flex flex-col gap-2">
              <CopyField value={props.protectedResourceMetadataUrl} label="protected resource metadata" />
              <CopyField value={props.authorizationServerMetadataUrl} label="authorization server metadata" />
            </div>
          </details>
          <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
            <Badge variant="secondary" className="font-mono">
              {props.protocolVersion}
            </Badge>
            {props.scopes.map((scope) => (
              <Badge key={scope} variant="outline" className="font-mono">
                {scope}
              </Badge>
            ))}
            <span>
              {props.tools.length} tool{props.tools.length === 1 ? "" : "s"}
            </span>
          </div>
        </div>
      </SectionCard>

      <SectionCard title="Availability" padded>
        <div className="divide-y">
          <ToggleRow
            id="mcp-enabled"
            label="MCP server"
            description="When off, the endpoint, the discovery documents and the OAuth endpoints answer 404. Existing grants stay stored and work again when it is turned back on."
            checked={settings.enabled}
            disabled={disabled}
            onChange={(enabled) => save({ ...settings, enabled })}
          />
          <ToggleRow
            id="mcp-registration"
            label="Let MCP clients register themselves"
            description="Dynamic client registration (RFC 7591). Turn it off when only pre-approved clients should connect; clients that need it will fail with a clear message."
            checked={settings.allowDynamicRegistration}
            disabled={disabled || !settings.enabled}
            onChange={(allowDynamicRegistration) => save({ ...settings, allowDynamicRegistration })}
          />
        </div>
        {!props.canWrite && (
          <p className="mt-3 text-xs text-muted-foreground">
            Changing these switches needs the settings:write permission.
          </p>
        )}
      </SectionCard>

      <SectionCard
        title="Connected apps"
        count={props.connections.length}
        description="Every live grant: the client, the account that approved it and what it may do. Disconnecting revokes its access and refresh tokens at once."
        padded={false}
      >
        {props.connections.length === 0 ? (
          <EmptyState
            icon={Plug}
            title="Nothing connected yet"
            description="Connect an MCP client to the endpoint above; it appears here after you approve it."
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Client</TableHead>
                <TableHead>Account</TableHead>
                <TableHead>Scopes</TableHead>
                <TableHead>Last used</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead className="w-[1%] text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {props.connections.map((connection) => (
                <TableRow key={connection.id}>
                  <TableCell className="font-medium">{connection.clientName}</TableCell>
                  <TableCell>
                    <span className="block">{connection.userName ?? connection.userEmail}</span>
                    {connection.userName && (
                      <span className="block text-xs text-muted-foreground">{connection.userEmail}</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <span className="flex flex-wrap gap-1">
                      {connection.scopes.map((scope) => (
                        <Badge key={scope} variant="outline" className="font-mono text-[11px]">
                          {scope}
                        </Badge>
                      ))}
                    </span>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{when(connection.lastUsedAt)}</TableCell>
                  <TableCell className="text-muted-foreground">{when(connection.refreshExpiresAt)}</TableCell>
                  <TableCell className="text-right">
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      disabled={!props.canWrite || revoking === `connections:${connection.id}`}
                      onClick={() => revoke("connections", String(connection.id), connection.clientName)}
                    >
                      <Trash2 aria-hidden="true" />
                      Disconnect
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </SectionCard>

      <SectionCard
        title="Registered clients"
        count={props.clients.length}
        description="Clients that registered themselves on this instance, whether or not they are connected. Revoking one also revokes every grant it holds."
        padded={false}
      >
        {props.clients.length === 0 ? (
          <EmptyState
            icon={ShieldCheck}
            title="No clients registered"
            description="A client registers when it starts an OAuth flow against the endpoint. Nothing to clean up yet."
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Client</TableHead>
                <TableHead>Redirect URI</TableHead>
                <TableHead>Registered</TableHead>
                <TableHead>Grants</TableHead>
                <TableHead className="w-[1%] text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {props.clients.map((client) => (
                <TableRow key={client.clientId}>
                  <TableCell>
                    <span className="block font-medium">{client.name}</span>
                    <span className="block font-mono text-[11px] text-muted-foreground">{client.clientId}</span>
                    {client.revokedAt && (
                      <Badge variant="destructive" className="mt-1">
                        Revoked
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className="max-w-[22rem]">
                    <span className="flex flex-col gap-0.5">
                      {client.redirectUris.map((uri) => (
                        <span key={uri} className="truncate font-mono text-xs text-muted-foreground" title={uri}>
                          {uri}
                        </span>
                      ))}
                    </span>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{when(client.createdAt)}</TableCell>
                  <TableCell>{client.activeGrants}</TableCell>
                  <TableCell className="text-right">
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      disabled={!props.canWrite || Boolean(client.revokedAt) || revoking === `clients:${client.clientId}`}
                      onClick={() => revoke("clients", client.clientId, client.name)}
                    >
                      <Trash2 aria-hidden="true" />
                      Revoke
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </SectionCard>

      <SectionCard title="Tools" description="What a connected client can call, and the permission each tool needs." padded={false}>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Tool</TableHead>
              <TableHead>Permission</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {props.tools.map((tool) => (
              <TableRow key={tool.name}>
                <TableCell>
                  <span className="block font-mono text-xs">{tool.name}</span>
                  <span className="block text-xs text-muted-foreground">{tool.title}</span>
                </TableCell>
                <TableCell>
                  {tool.permission ? (
                    <Badge variant="outline" className="font-mono text-[11px]">
                      {tool.permission}
                    </Badge>
                  ) : (
                    <span className="text-xs text-muted-foreground">Any signed-in account</span>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </SectionCard>
    </div>
  );
}
