-- The MCP authorization server (src/lib/mcp/oauth.ts): dynamically
-- registered OAuth 2.1 clients, the scopes a user approved for one, the
-- single-use authorization codes, and the access/refresh token pairs.
-- Only hashes of secrets and tokens are stored.
CREATE TABLE `mcp_oauth_clients` (
	`clientId` text PRIMARY KEY NOT NULL,
	`clientSecretHash` text,
	`name` text NOT NULL,
	`redirectUris` text NOT NULL,
	`grantTypes` text DEFAULT '["authorization_code","refresh_token"]' NOT NULL,
	`tokenEndpointAuthMethod` text DEFAULT 'none' NOT NULL,
	`clientUri` text,
	`logoUri` text,
	`softwareId` text,
	`softwareVersion` text,
	`createdAt` text NOT NULL,
	`lastUsedAt` text,
	`revokedAt` text
);
--> statement-breakpoint
CREATE INDEX `mcp_oauth_clients_revoked_idx` ON `mcp_oauth_clients` (`revokedAt`);--> statement-breakpoint
CREATE TABLE `mcp_oauth_consents` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`userId` integer NOT NULL,
	`clientId` text NOT NULL,
	`scopes` text NOT NULL,
	`resource` text NOT NULL,
	`createdAt` text NOT NULL,
	`updatedAt` text NOT NULL,
	FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `mcp_oauth_consents_user_client_unique` ON `mcp_oauth_consents` (`userId`,`clientId`);--> statement-breakpoint
CREATE TABLE `mcp_oauth_codes` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`codeHash` text NOT NULL,
	`clientId` text NOT NULL,
	`userId` integer NOT NULL,
	`redirectUri` text NOT NULL,
	`codeChallenge` text NOT NULL,
	`scopes` text NOT NULL,
	`resource` text NOT NULL,
	`createdAt` text NOT NULL,
	`expiresAt` text NOT NULL,
	`consumedAt` text,
	FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `mcp_oauth_codes_code_hash_unique` ON `mcp_oauth_codes` (`codeHash`);--> statement-breakpoint
CREATE INDEX `mcp_oauth_codes_user_idx` ON `mcp_oauth_codes` (`userId`);--> statement-breakpoint
CREATE TABLE `mcp_oauth_tokens` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`accessTokenHash` text NOT NULL,
	`refreshTokenHash` text,
	`clientId` text NOT NULL,
	`userId` integer NOT NULL,
	`scopes` text NOT NULL,
	`resource` text NOT NULL,
	`accessExpiresAt` text NOT NULL,
	`refreshExpiresAt` text NOT NULL,
	`familyId` text NOT NULL,
	`createdAt` text NOT NULL,
	`lastUsedAt` text,
	`rotatedAt` text,
	`revokedAt` text,
	FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `mcp_oauth_tokens_access_hash_unique` ON `mcp_oauth_tokens` (`accessTokenHash`);--> statement-breakpoint
CREATE UNIQUE INDEX `mcp_oauth_tokens_refresh_hash_unique` ON `mcp_oauth_tokens` (`refreshTokenHash`);--> statement-breakpoint
CREATE INDEX `mcp_oauth_tokens_family_idx` ON `mcp_oauth_tokens` (`familyId`);--> statement-breakpoint
CREATE INDEX `mcp_oauth_tokens_user_idx` ON `mcp_oauth_tokens` (`userId`);
