/**
 * Scores secret protection on labeled cases: what must never reach the model, and what must.
 *
 *   node test/secrets-eval.ts [cases.json…]     # default: every file in test/secret-cases/
 *   node test/secrets-eval.ts --json …           # machine-readable results
 *
 * Results, and what pi-safety promises about each:
 *   LEAK  a replaceable value from a secret file or credential-named variable reached the model. Must be 0.
 *   weak  a known value too ordinary to replace everywhere (`postgres`, a 4-digit PIN). Only masked reads
 *         and prints of the file hide these. Reported, not failed.
 *   leak  a secret pi-safety never saw, caught only by patterns. Best effort. Reported, not failed.
 *   LOST  harmless text the agent needs was hidden. Must be 0.
 *   SLOW  scrubbing took longer than the case's maxMs (default 1000). Must be 0.
 *
 *   node test/secrets-eval.ts --broad …          # with the opt-in "broad" patterns
 *
 * Each case runs in a fresh project directory with its own home directory and environment, through
 * Secrets.scrub(), the same code the extension applies to tool results. A case file is a JSON array of:
 *
 *   {
 *     "id": "rails-master-key",
 *     "why": "what this case tests",
 *     "files": { ".env": "…", "~/.aws/credentials": "…" },   // "~/" is the fake home
 *     "env": { "GITHUB_TOKEN": "ghp_…" },                     // the process environment
 *     "read": ".env",                                         // a read-tool call of this file
 *     "output": "…",                                          // and/or any other tool's output,
 *     "command": "cat .env",                                  // from this command, if a shell one
 *     "hide": ["values that must not appear"],
 *     "keep": ["text that must survive"],
 *     "maxMs": 500                                            // fail if scrubbing takes longer (default 1000)
 *   }
 */

import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { isCredentialName, isReplaceable, Secrets } from "../secrets.ts";
import { expandMarkers } from "./markers.ts";

interface Case {
	id: string;
	why?: string;
	files?: Record<string, string>;
	env?: Record<string, string>;
	read?: string;
	output?: string;
	command?: string;
	hide?: string[];
	keep?: string[];
	maxMs?: number;
}

interface Result {
	file: string;
	id: string;
	leaked: string[];
	/** Leaked values pi-safety knew and could replace: they were in a secret file or credential variable. */
	leakedKnown: string[];
	/** Leaked values it knew but that are too ordinary to replace everywhere. */
	leakedWeak: string[];
	lost: string[];
	slow?: number;
	result: string;
}

const args = process.argv.slice(2);
const asJson = args.includes("--json");
const broad = args.includes("--broad");
let files = args.filter((a) => !a.startsWith("--"));
if (!files.length) {
	const dir = join(import.meta.dirname, "secret-cases");
	files = readdirSync(dir)
		.filter((f) => f.endsWith(".json"))
		.map((f) => join(dir, f));
}

const originalEnv = { ...process.env };

function setEnv(env: Record<string, string | undefined>) {
	for (const name of Object.keys(process.env)) delete process.env[name];
	for (const [name, value] of Object.entries(env)) if (value !== undefined) process.env[name] = value;
}

function run(file: string, item: Case): Result {
	const root = mkdtempSync(join(tmpdir(), "pi-safety-case-"));
	const home = join(root, "home");
	const cwd = join(root, "project");
	mkdirSync(home);
	mkdirSync(cwd);
	const place = (path: string) => (path.startsWith("~/") ? join(home, path.slice(2)) : resolve(cwd, path));
	for (const [path, content] of Object.entries(item.files ?? {})) {
		mkdirSync(dirname(place(path)), { recursive: true });
		writeFileSync(place(path), content);
	}
	// Only the case's environment, so the runner's own variables and home directory don't count.
	// process.env must be edited in place: assigning a new object doesn't reach os.homedir().
	setEnv({ PATH: originalEnv.PATH, HOME: home, ...item.env });
	try {
		const secrets = new Secrets({ mode: "mask", patterns: broad ? "broad" : "precise", paths: [], notSecret: [], agentDir: join(home, ".pi/agent") });
		const known = [
			...Object.entries(item.files ?? {}).filter(([path]) => secrets.isSecret(place(path))).map(([, content]) => content),
			...Object.entries(item.env ?? {}).filter(([name]) => isCredentialName(name)).map(([, value]) => value),
		];
		const parts: string[] = [];
		const started = performance.now();
		if (item.read) {
			const path = place(item.read);
			parts.push(secrets.scrub(readFileSync(path, "utf8"), cwd, secrets.isSecret(path), basename(path)));
		}
		if (item.output !== undefined) parts.push(secrets.scrub(item.output, cwd, false, "", item.command ?? ""));
		const result = parts.join("\n");
		const ms = performance.now() - started;
		return {
			file,
			id: item.id,
			slow: ms > (item.maxMs ?? 1000) ? Math.round(ms) : undefined,
			leaked: (item.hide ?? []).filter((v) => result.includes(v)),
			leakedKnown: (item.hide ?? []).filter((v) => result.includes(v) && known.some((k) => k.includes(v)) && isReplaceable(v)),
			leakedWeak: (item.hide ?? []).filter((v) => result.includes(v) && known.some((k) => k.includes(v)) && !isReplaceable(v)),
			lost: (item.keep ?? []).filter((v) => !result.includes(v)),
			result,
		};
	} finally {
		setEnv(originalEnv);
		rmSync(root, { recursive: true, force: true });
	}
}

const results: Result[] = [];
for (const file of files) {
	// The stored cases keep credential prefixes as markers; see test/markers.ts.
	const cases: Case[] = JSON.parse(expandMarkers(readFileSync(file, "utf8")));
	for (const item of cases) {
		try {
			results.push(run(file, item));
		} catch (err) {
			results.push({ file, id: item.id, leaked: [], leakedKnown: [], leakedWeak: [], lost: [`(error: ${(err as Error).message})`], result: "" });
		}
	}
}

const failed = results.filter((r) => r.leakedKnown.length || r.lost.length || r.slow);
const reported = results.filter((r) => r.leaked.length && !r.leakedKnown.length);
if (asJson) {
	console.log(JSON.stringify({ total: results.length, failed: failed.length, failures: [...failed, ...reported] }, null, 1));
} else {
	const verbose = args.includes("--verbose");
	for (const r of [...failed, ...(verbose ? reported : [])]) {
		const where = r.file.split("/").at(-1);
		const kind = r.leakedKnown.length ? "LEAK" : r.leakedWeak.length ? "weak" : "leak";
		if (r.leaked.length) console.log(`${kind} ${where} ${r.id}: ${r.leaked.map((v) => JSON.stringify(v).slice(0, 120)).join(", ")}`);
		if (r.lost.length) console.log(`LOST ${where} ${r.id}: ${r.lost.map((v) => JSON.stringify(v)).join(", ")}`);
		if (r.slow) console.log(`SLOW ${where} ${r.id}: ${r.slow} ms`);
	}
	const known = results.filter((r) => r.leakedKnown.length).length;
	const weak = results.filter((r) => !r.leakedKnown.length && r.leakedWeak.length).length;
	const unknown = results.filter((r) => r.leaked.length && !r.leakedKnown.length && !r.leakedWeak.length).length;
	const lost = results.filter((r) => r.lost.length).length;
	const slow = results.filter((r) => r.slow).length;
	console.log(
		`\n${results.length} cases (${broad ? "broad" : "precise"} patterns): ${known} LEAK · ${lost} LOST · ${slow} SLOW` +
			`  |  reported: ${weak} weak · ${unknown} leak of unknown secrets  (--verbose lists them)`,
	);
}
process.exitCode = failed.length ? 1 : 0;
