import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";

const root = process.cwd();
const dockerfile = readFileSync(join(root, "docker/caddy/Dockerfile"), "utf8");
const goMod = readFileSync(join(root, "docker/caddy/go.mod"), "utf8");
const buildScript = readFileSync(join(root, "docker/caddy/build.sh"), "utf8");
const toolsFile = readFileSync(join(root, "docker/caddy/tools.go"), "utf8");
const compatibilityUpdater = readFileSync(
  join(root, "docker/caddy/update-compatibility-pins.sh"),
  "utf8"
);
const dependabot = readFileSync(join(root, ".github/dependabot.yml"), "utf8");
const compatibilityWorkflow = readFileSync(
  join(root, ".github/workflows/caddy-compatibility-pins.yml"),
  "utf8"
);

describe("reproducible Caddy build", () => {
  it("pins Caddy, xcaddy, plugins, and multi-architecture base images", () => {
    expect(dockerfile).not.toMatch(/@latest|xcaddy build master/);
    expect(dockerfile.split("\n")[0]).toMatch(/^# syntax=.+@sha256:[a-f0-9]{64}$/);
    for (const line of dockerfile.split("\n").filter((line) => line.startsWith("FROM "))) {
      expect(line).toMatch(/@sha256:[a-f0-9]{64}(?:\s|$)/);
    }

    expect(goMod).toMatch(/github\.com\/caddyserver\/caddy\/v2 v\d+\.\d+\.\d+/);
    expect(goMod).toMatch(/github\.com\/caddyserver\/xcaddy v\d+\.\d+\.\d+/);
    expect(goMod).not.toContain("latest");
    // Caddy before 2.11.7 imported github.com/google/cel-go, pinned to Caddy's
    // version; from 2.11.7 Caddy imports cel.dev/cel-go and needs no pin.
    expect(goMod).toMatch(
      /replace github\.com\/google\/cel-go => github\.com\/google\/cel-go v\d+\.\d+\.\d+|\bcel\.dev\/cel-go v\d+\.\d+\.\d+/
    );
  });

  it("resolves every plugin from go.mod and enables Dependabot autobumps", () => {
    const requiredModules = new Set(
      goMod.split("\n")
        .map((line) => line.trim().match(/^(github\.com\/\S+)\s+v\S+$/)?.[1])
        .filter((module): module is string => Boolean(module))
    );
    const plugins = buildScript
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.startsWith("github.com/") && !line.includes("caddyserver/caddy"));

    expect(plugins.length).toBeGreaterThan(0);
    // Every build module must also be blank-imported in tools.go, otherwise
    // `go mod tidy` (run by Dependabot) prunes the require from go.mod.
    for (const plugin of plugins) {
      expect(requiredModules.has(plugin)).toBe(true);
      expect(toolsFile).toContain(`_ "${plugin}"`);
    }
    expect(buildScript).toContain('module_version "$module"');
    expect(buildScript).toContain('--replace "github.com/google/cel-go=github.com/google/cel-go@$cel_go_version"');
    expect(dockerfile).toContain("RUN sh ./update-compatibility-pins.sh");
    expect(dependabot).toMatch(/package-ecosystem: "gomod"[\s\S]*directory: "\/docker\/caddy"/);
  });

  it("autobumps the replacement pin through a scheduled, build-gated workflow", () => {
    expect(compatibilityUpdater).toContain('github.com/caddyserver/caddy/v2@${caddy_version}');
    expect(compatibilityUpdater).toContain("go mod edit");
    expect(compatibilityUpdater).toContain('github.com/google/cel-go@${cel_go_version}');
    expect(compatibilityWorkflow).toMatch(/schedule:[\s\S]*cron:/);
    expect(compatibilityWorkflow).toContain("workflow_dispatch:");
    expect(compatibilityWorkflow).toContain("sh docker/caddy/update-compatibility-pins.sh");
    expect(compatibilityWorkflow).toContain("docker compose build caddy");
    expect(compatibilityWorkflow).toContain("gh pr create");
  });
});

describe.skipIf(process.platform === "win32")("xcaddy transitive security pin", () => {
  function runBuild(compress: string, cel = "") {
    const dir = mkdtempSync(join(tmpdir(), "ingressi-caddy-build-"));
    const capture = join(dir, "xcaddy.json");
    try {
      // Run the real build script, but capture the external build command.
      // No Go download, Docker access or /usr/bin/caddy write occurs here.
      writeFileSync(join(dir, "go"), `#!/bin/sh
case "$5" in
  github.com/klauspost/compress) printf '%s\\n' "$TEST_COMPRESS_VERSION" ;;
  github.com/google/cel-go) printf '%s\\n' "$TEST_CEL_VERSION" ;;
  github.com/caddyserver/caddy/v2) printf '%s\\n' 'v2.11.9' ;;
  *) printf '%s\\n' 'v0.1.0' ;;
esac
`);
      writeFileSync(join(dir, "xcaddy"), `#!${process.execPath}
require("node:fs").writeFileSync(process.env.XCADDY_CAPTURE, JSON.stringify({
  args: process.argv.slice(2), goos: process.env.GOOS, goarch: process.env.GOARCH
}));
`);
      chmodSync(join(dir, "go"), 0o700);
      chmodSync(join(dir, "xcaddy"), 0o700);
      const result = spawnSync("sh", [join(root, "docker/caddy/build.sh")], {
        cwd: dir,
        encoding: "utf8",
        env: {
          ...process.env, PATH: `${dir}:${process.env.PATH}`,
          TEST_COMPRESS_VERSION: compress, TEST_CEL_VERSION: cel,
          XCADDY_CAPTURE: capture, TARGETOS: "linux", TARGETARCH: "amd64",
        },
      });
      const command = existsSync(capture)
        ? JSON.parse(readFileSync(capture, "utf8")) as { args: string[]; goos: string; goarch: string }
        : null;
      return { result, command };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  it("carries the resolved compression version into xcaddy's separate module", () => {
    const { result, command } = runBuild("v1.20.2");
    expect(result.status, result.stderr).toBe(0);
    expect(command?.args.slice(0, 2)).toEqual(["build", "v2.11.9"]);
    expect(command?.args.filter((_, i, args) => args[i - 1] === "--replace")).toEqual([
      "github.com/klauspost/compress=github.com/klauspost/compress@v1.20.2",
    ]);
    expect(command?.goos).toBe("linux");
    expect(command?.goarch).toBe("amd64");
  });

  it("follows a newer resolved version while preserving a legacy cel replacement", () => {
    const { result, command } = runBuild("v1.20.3", "v0.26.0");
    expect(result.status, result.stderr).toBe(0);
    expect(command?.args.filter((_, i, args) => args[i - 1] === "--replace")).toEqual([
      "github.com/klauspost/compress=github.com/klauspost/compress@v1.20.3",
      "github.com/google/cel-go=github.com/google/cel-go@v0.26.0",
    ]);
  });

  it("refuses to build when the compression security pin cannot be resolved", () => {
    const { result, command } = runBuild("");
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("No pinned version found for github.com/klauspost/compress");
    expect(command).toBeNull();
  });
});
