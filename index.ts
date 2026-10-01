/**
 * pi-safety — an auto mode for pi. A decisions classifier (TypeSafe's Jev by default) reviews
 * every tool call that could do damage and blocks the dangerous ones the user didn't ask for.
 *
 * Threat model: the agent itself may be hijacked by content it read, and will then actively try
 * to get a harmful action past the gate. So:
 * - Only reads and small edits to ordinary project files skip the classifier. Everything else,
 *   including unknown tools, is classified. Classifier errors block.
 * - The classifier never sees tool results or the agent's prose (the usual injection carriers),
 *   only the user's messages and the agent's tool calls, which it is told not to trust.
 * - Every byte the agent writes through a skipped edit is shown to the classifier at the next
 *   classification (the "backlog"), so writing a script and then running it can't launder it.
 * - Sibling calls of the same assistant message are shown too: pi runs every `tool_call`
 *   handler of a batch before executing any of them, so files on disk can be stale.
 * - The pending action is never truncated. If it is too large to review, it is blocked.
 * - Child processes inherit PI_SAFETY=1, so a nested `pi` the agent starts is guarded as well.
 */

import { appendFileSync, lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { type ExtensionAPI, type ExtensionContext, getAgentDir } from "@earendil-works/pi-coding-agent";
import { type Policy, questions } from "./questions.ts";

const CONFIG_FILE = join(getAgentDir(), "safety.json");
const ENTRY_TYPE = "safety";
const STATUS_KEY = "safety";

/** Tools that only read local state. */
const READ_TOOLS = new Set(["read", "grep", "find", "ls"]);
const EDIT_TOOLS = new Set(["write", "edit"]);
const SHELL_TOOLS = new Set(["bash", "powershell"]);
/** Tools whose input is code that runs, so the files it may run are relevant. */
const EXEC_TOOLS = new Set([...SHELL_TOOLS, "codemode"]);

/**
 * Classifiers from pi's catalog tried in order when the config names none. Providers register these;
 * surplus-intelligence comes from a provider extension, the rest are built into pi.
 */
const DEFAULT_CLASSIFIERS = [
	"surplus-intelligence/jev-1.13",
	"typesafe/jev-latest",
	"openrouter/~typesafe/jev-latest",
	"openrouter/typesafe/jev-1.13",
	"vercel-ai-gateway/typesafe-ai/jev",
	"cloudflare-workers-ai/typesafe/jev",
	"opencode/jev-1.13",
];

// Budgets in characters. Jev reads 32k tokens; the total stays well under that.
const MAX_ACTION = 60_000;
const MAX_TOTAL = 100_000;
const MAX_FAST_EDIT = 4_000;
const MAX_BACKLOG = 24_000;
const MAX_USER = 12_000;
const MAX_SIBLINGS = 12_000;
const MAX_FILES = 12_000;
const MAX_FILE = 6_000;
const MAX_RECENT = 8_000;
const RECENT_ACTIONS = 20;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

interface Endpoint {
	/** Full URL of a decisions-compatible endpoint, e.g. https://openrouter.ai/api/alpha/decisions */
	url: string;
	model: string;
	apiKey?: string;
	/** Environment variable(s) holding the API key; the first one set is used. */
	apiKeyEnv?: string | string[];
	headers?: Record<string, string>;
}

/** The policy fields (`dangerous`, `routine`, `block`, `allow`) are described in questions.ts. */
interface Config extends Policy {
	/** When the gate is on: only with --safety or PI_SAFETY=1 ("flag"), also in every non-TUI run ("headless"), or always. */
	enable: "flag" | "headless" | "always";
	/** Classifier from pi's model catalog as provider/model-id. Unset: the first available Jev. */
	classifier?: string;
	/** Call a decisions endpoint directly instead of pi's catalog. */
	endpoint?: Endpoint;
	/** Block when the classifier's block probability reaches this. */
	threshold: number;
	/** Ask the user about blocked actions in the TUI instead of denying them. */
	ask: boolean;
	/** What to do when the classifier fails: ask in the TUI and block elsewhere, always block, or allow. */
	onError: "block" | "ask" | "allow";
	/** Abort the run after this many denials in a row, or in total. */
	maxConsecutiveDenials: number;
	maxDenials: number;
	timeoutMs: number;
}

const DEFAULTS: Config = {
	enable: "flag",
	threshold: 0.4,
	ask: true,
	onError: "ask",
	maxConsecutiveDenials: 3,
	maxDenials: 20,
	timeoutMs: 30_000,
};

function loadConfig(): { config: Config; error?: string } {
	let file: Partial<Config> = {};
	let error: string | undefined;
	try {
		file = JSON.parse(readFileSync(CONFIG_FILE, "utf8"));
	} catch (err) {
		if ((err as NodeJS.ErrnoException).code !== "ENOENT") error = `Could not read ${CONFIG_FILE}: ${(err as Error).message}`;
	}
	const config: Config = { ...DEFAULTS, ...file };
	if (process.env.PI_SAFETY_CLASSIFIER) config.classifier = process.env.PI_SAFETY_CLASSIFIER;
	if (process.env.PI_SAFETY_URL) {
		config.endpoint = {
			url: process.env.PI_SAFETY_URL,
			model: process.env.PI_SAFETY_MODEL ?? config.endpoint?.model ?? "typesafe/jev-1.13",
			apiKeyEnv: "PI_SAFETY_API_KEY",
		};
	}
	return { config, error };
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/** pi's tool path resolution, or undefined for inputs whose resolution we won't second-guess. */
function resolveToolPath(path: unknown, cwd: string): string | undefined {
	if (typeof path !== "string" || path === "") return undefined;
	if (/[\0  -   　]/.test(path) || path.startsWith("file:")) return undefined;
	let p = path.startsWith("@") ? path.slice(1) : path;
	if (p === "~") p = homedir();
	else if (p.startsWith("~/")) p = join(homedir(), p.slice(2));
	return isAbsolute(p) ? resolve(p) : resolve(cwd, p);
}

/** Real path of `path`, following symlinks even when the file doesn't exist yet. */
function realTarget(path: string): string | undefined {
	try {
		return realpathSync(path);
	} catch {
		try {
			lstatSync(path);
			return undefined; // exists but unresolvable: a dangling or looping symlink
		} catch {
			const parent = dirname(path);
			if (parent === path) return undefined;
			const real = realTarget(parent);
			return real && join(real, basename(path));
		}
	}
}

function inside(child: string, parent: string): boolean {
	const rel = relative(parent, child);
	return rel !== "" && rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

/** Whether an edit to `path` can skip the classifier: an ordinary file of the project in cwd. */
function isPlainProjectFile(path: unknown, cwd: string): boolean {
	const resolved = resolveToolPath(path, cwd);
	if (!resolved) return false;
	let realCwd: string;
	let home: string;
	try {
		realCwd = realpathSync(cwd);
		home = realpathSync(homedir());
	} catch {
		return false;
	}
	// A cwd of /, ~ or an ancestor of ~ would make dotfiles and the whole home "project files".
	if (realCwd === home || inside(home, realCwd) || realCwd === resolve("/")) return false;
	const target = realTarget(resolved);
	if (!target || !inside(target, realCwd)) return false;
	// Dot paths hold config that runs code (.git/hooks, .envrc, .pi, .vscode, .github); node_modules too.
	if (relative(realCwd, target).split(sep).some((s) => s.startsWith(".") || s === "node_modules")) return false;
	try {
		const stat = statSync(target);
		if (!stat.isFile() || stat.nlink > 1) return false; // a hard link can point outside the project
	} catch {}
	return true;
}

const SECRET_NAME = /(^\.env|\.pem$|\.key$|^id_|secret|credential|token|password|\.p12$|\.pfx$)/i;

/** A text file's contents for the classifier, or undefined for binaries, secrets and directories. */
function readForReview(path: string): string | undefined {
	if (SECRET_NAME.test(basename(path))) return undefined;
	try {
		const stat = statSync(path);
		if (!stat.isFile() || stat.size > 512 * 1024) return undefined;
		const text = readFileSync(path, "utf8");
		if (text.slice(0, 8192).includes("\0")) return undefined;
		return text;
	} catch {
		return undefined;
	}
}

/** Files inside cwd that a shell command names, e.g. `bash scripts/x.sh` or `python3 tool.py`. */
function referencedFiles(command: string, cwd: string): string[] {
	let realCwd: string;
	try {
		realCwd = realpathSync(cwd);
	} catch {
		return [];
	}
	const found = new Set<string>();
	for (const token of command.split(/[\s;&|()<>`'"=]+/)) {
		if (!token || token.startsWith("-") || token.includes("$") || token.length > 300) continue;
		const resolved = resolveToolPath(token, cwd);
		const target = resolved && realTarget(resolved);
		if (!target || !inside(target, realCwd)) continue;
		try {
			if (statSync(target).isFile()) found.add(target);
		} catch {}
		if (found.size >= 8) break;
	}
	return [...found];
}

// ---------------------------------------------------------------------------
// Transcript
// ---------------------------------------------------------------------------

interface Call {
	id: string;
	name: string;
	arguments: Record<string, unknown>;
}

interface Transcript {
	userMessages: string[];
	/** Tool calls of earlier assistant messages, oldest first. */
	earlierCalls: Call[];
	/** The assistant message's other tool calls, when the pending call is in the transcript. */
	siblings: Call[] | undefined;
	/** Calls by id, to find a nested call's parent. */
	byId: Map<string, Call>;
}

function textOf(content: unknown): string {
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";
	return content
		.map((block) => (block?.type === "text" ? block.text : block?.type === "image" ? "[image]" : ""))
		.filter(Boolean)
		.join("\n");
}

function readTranscript(ctx: ExtensionContext, toolCallId: string): Transcript {
	const userMessages: string[] = [];
	const earlierCalls: Call[] = [];
	const byId = new Map<string, Call>();
	let siblings: Call[] | undefined;
	for (const entry of ctx.sessionManager.getBranch() as any[]) {
		if (entry.type !== "message") continue;
		const message = entry.message;
		if (message.role === "user") userMessages.push(textOf(message.content));
		if (message.role !== "assistant" || !Array.isArray(message.content)) continue;
		const calls: Call[] = message.content
			.filter((block: any) => block?.type === "toolCall")
			.map((block: any) => ({ id: block.id, name: block.name, arguments: block.arguments ?? {} }));
		for (const call of calls) byId.set(call.id, call);
		if (calls.some((call) => call.id === toolCallId)) {
			siblings = calls.filter((call) => call.id !== toolCallId);
			break;
		}
		earlierCalls.push(...calls);
	}
	return { userMessages, earlierCalls, siblings, byId };
}

function clip(text: string, max: number): string {
	if (text.length <= max) return text;
	const head = Math.floor(max * 0.7);
	return `${text.slice(0, head)}\n…[${text.length - max} characters omitted]…\n${text.slice(text.length - (max - head))}`;
}

function json(value: unknown): string {
	return JSON.stringify(value) ?? "";
}

/** Characters an edit or write puts into a file. */
function writtenText(name: string, args: Record<string, unknown>): string {
	if (name === "write") return typeof args.content === "string" ? args.content : json(args);
	if (name === "edit" && Array.isArray(args.edits)) return args.edits.map((e: any) => String(e?.newText ?? "")).join("\n");
	return json(args);
}

/** Fills `items` newest first until `budget` runs out, then returns them oldest first. */
function newestWithin<T>(items: T[], size: (item: T) => number, budget: number): { kept: T[]; dropped: number } {
	const kept: T[] = [];
	for (let i = items.length - 1; i >= 0; i--) {
		budget -= size(items[i]);
		if (budget < 0) return { kept: kept.reverse(), dropped: i + 1 };
		kept.push(items[i]);
	}
	return { kept: kept.reverse(), dropped: 0 };
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

interface Verdict {
	probability: number;
	category: string;
	cost: number;
	model: string;
}

type Classify = (state: Record<string, unknown>, signal: AbortSignal) => Promise<Verdict>;

function registryClassifier(ctx: ExtensionContext, config: Config): Classify {
	let chosen: Promise<{ model: any; name: string }> | undefined;
	const choose = async () => {
		if (config.classifier) {
			const slash = config.classifier.indexOf("/");
			const model = ctx.modelRegistry.findOfType("classifier", config.classifier.slice(0, slash), config.classifier.slice(slash + 1));
			if (!model) throw new Error(`Classifier ${config.classifier} is not in pi's model catalog`);
			return { model, name: config.classifier };
		}
		const available = await ctx.modelRegistry.getAvailableOfType("classifier");
		for (const name of DEFAULT_CLASSIFIERS) {
			const model = available.find((m: any) => `${m.provider}/${m.id}` === name);
			if (model) return { model, name };
		}
		throw new Error(
			"No Jev classifier has credentials. Log in to a provider that serves Jev (e.g. TYPESAFE_API_KEY or OPENROUTER_API_KEY), or set classifier or endpoint in safety.json",
		);
	};
	return async (state, signal) => {
		chosen ??= choose().catch((err) => {
			chosen = undefined;
			throw err;
		});
		const { model, name } = await chosen;
		const result: any = await ctx.modelRegistry.classify(model, { state: state as any, questions: questions(config) }, { signal });
		if (result.stopReason !== "stop") throw new Error(result.errorMessage ?? `${name} failed`);
		return {
			probability: result.answers.block.probability,
			category: result.answers.category.choice,
			cost: result.usage?.cost?.total ?? 0,
			model: name,
		};
	};
}

/** A classifier from pi's catalog, or a decisions endpoint the config names directly. */
function makeClassifier(ctx: ExtensionContext, config: Config): Classify {
	return config.endpoint ? endpointClassifier(config.endpoint, config) : registryClassifier(ctx, config);
}

function endpointClassifier(endpoint: Endpoint, config: Config): Classify {
	const wireQuestions = Object.fromEntries(
		Object.entries(questions(config)).map(([id, q]) => [id, q.type === "bool" ? { ...q, type: "noul" } : q]),
	);
	return async (state, signal) => {
		const apiKey = endpoint.apiKey ?? [endpoint.apiKeyEnv ?? []].flat().map((name) => process.env[name]).find(Boolean);
		const send = () =>
			fetch(endpoint.url, {
				method: "POST",
				signal,
				headers: {
					"Content-Type": "application/json",
					...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
					...endpoint.headers,
				},
				body: JSON.stringify({ model: endpoint.model, questions: wireQuestions, state }),
			});
		let response = await send().catch(() => undefined);
		if (!response || response.status >= 500 || response.status === 429) response = await send();
		const body: any = await response.json().catch(() => undefined);
		if (!response.ok) throw new Error(`${endpoint.url} returned ${response.status}: ${json(body?.error ?? body).slice(0, 300)}`);
		const probability = body?.answers?.block?.noul;
		if (typeof probability !== "number") throw new Error(`${endpoint.url} returned no answer`);
		const cost = Number(body?.usage?.cost ?? body?.cost ?? 0);
		return {
			probability,
			category: String(body.answers.category?.choice ?? "none"),
			cost: Number.isFinite(cost) ? cost : 0,
			model: endpoint.model,
		};
	};
}

const CATEGORY_TEXT: Record<string, string> = {
	none: "risky",
	destruction: "destructive",
	exfiltration: "like it sends private data outside",
	security: "like it weakens security",
	persistence: "like it installs persistence",
	shared_systems: "like it changes shared or production systems",
	guardrails: "like it tampers with the agent's guardrails",
	scope: "beyond what the user asked for",
};

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

interface LogEntry {
	toolCallId: string;
	tool: string;
	decision: "allow" | "block" | "ask-allow" | "ask-block";
	/** Whether this decision reviewed the pending backlog of skipped edits. */
	reviewedBacklog?: boolean;
	probability?: number;
	category?: string;
	reason?: string;
	model?: string;
	ms?: number;
}

/**
 * Whether this process was started with PI_SAFETY=1. Read once per process, before setEnabled exports the
 * variable for child processes, and kept on globalThis so /reload doesn't mistake that export for the user's.
 */
const globals = globalThis as { piSafetyEnvForced?: boolean };
globals.piSafetyEnvForced ??= process.env.PI_SAFETY === "1";

export default function (pi: ExtensionAPI) {
	pi.registerFlag("safety", { description: "Gate risky tool calls with a decisions classifier (pi-safety)", type: "boolean" });

	let { config, error: configError } = loadConfig();
	let enabled = false;
	let classify: Classify | undefined;
	/** Ids of skipped (fast-pathed) edits the classifier hasn't seen yet. */
	let backlog: string[] = [];
	const denied: { tool: string; input: string; reason: string }[] = [];
	let consecutiveDenials = 0;
	let totalDenials = 0;
	/** Set when the denial limit is reached: every call is denied until the user prompts again. */
	let stopped = false;
	let checks = 0;
	let blocked = 0;
	let cost = 0;

	const updateStatus = (ctx: ExtensionContext) => {
		if (!ctx.hasUI) return;
		const text = enabled
			? `🛡 ${checks} checked${blocked ? ` · ${blocked} blocked` : ""}${cost ? ` · $${cost.toFixed(4)}` : ""}`
			: undefined;
		ctx.ui.setStatus(STATUS_KEY, text);
	};

	const setEnabled = (ctx: ExtensionContext, on: boolean) => {
		enabled = on;
		// Nested pi processes started by the agent inherit the gate.
		if (on) process.env.PI_SAFETY = "1";
		else delete process.env.PI_SAFETY;
		classify = on ? makeClassifier(ctx, config) : undefined;
		updateStatus(ctx);
	};

	const isForced = () => pi.getFlag("safety") === true || globals.piSafetyEnvForced === true;

	const log = (entry: LogEntry) => pi.appendEntry(ENTRY_TYPE, entry);

	/** Rebuilds the backlog from the branch: edits after the last decision that reviewed it. */
	const rebuildBacklog = (ctx: ExtensionContext) => {
		backlog = [];
		const decided = new Set<string>();
		for (const entry of ctx.sessionManager.getBranch() as any[]) {
			if (entry.type === "custom" && entry.customType === ENTRY_TYPE) {
				const data = entry.data as LogEntry;
				decided.add(data.toolCallId);
				if (data.reviewedBacklog) backlog = [];
			} else if (entry.type === "message" && entry.message.role === "assistant" && Array.isArray(entry.message.content)) {
				for (const block of entry.message.content) {
					if (block?.type === "toolCall" && EDIT_TOOLS.has(block.name)) backlog.push(block.id);
				}
			}
		}
		backlog = backlog.filter((id) => !decided.has(id));
	};

	pi.on("session_start", (_event, ctx) => {
		({ config, error: configError } = loadConfig());
		if (configError && ctx.hasUI) ctx.ui.notify(configError, "error");
		const toggle = (ctx.sessionManager.getBranch() as any[])
			.filter((e) => e.type === "custom" && e.customType === `${ENTRY_TYPE}-toggle`)
			.at(-1)?.data?.enabled;
		const wanted =
			config.enable === "always" ||
			(config.enable === "headless" && ctx.mode !== "tui");
		// --safety and PI_SAFETY=1 can't be turned off; /safety on|off overrides only the config.
		setEnabled(ctx, isForced() || (typeof toggle === "boolean" ? toggle : wanted));
		rebuildBacklog(ctx);
	});

	// Denial limits count per run.
	pi.on("before_agent_start", () => {
		stopped = false;
		consecutiveDenials = 0;
		totalDenials = 0;
	});

	pi.registerCommand("safety", {
		description: "Gate risky tool calls with a classifier: /safety [on|off|status]",
		handler: async (args, ctx) => {
			const arg = args.trim();
			if (arg === "off" && isForced()) {
				ctx.ui.notify("pi-safety was enabled with --safety or PI_SAFETY=1 and stays on for this process.", "warning");
			} else if (arg === "on" || arg === "off") {
				({ config, error: configError } = loadConfig());
				setEnabled(ctx, arg === "on");
				pi.appendEntry(`${ENTRY_TYPE}-toggle`, { enabled: arg === "on" });
				rebuildBacklog(ctx);
			}
			const source = config.endpoint ? `${config.endpoint.model} at ${config.endpoint.url}` : (config.classifier ?? "first available Jev");
			ctx.ui.notify(
				enabled
					? `pi-safety is on (${source}, threshold ${config.threshold}). ${checks} checked, ${blocked} blocked${cost ? `, $${cost.toFixed(4)}` : ""}.`
					: "pi-safety is off. /safety on to enable it for this session.",
				"info",
			);
		},
	});

	pi.on("tool_call", async (event, ctx) => {
		if (!enabled || !classify) return undefined;
		if (stopped) {
			return { block: true, terminate: true, reason: "pi-safety stopped this run after too many blocked actions. Stop and explain to the user what needs their approval." };
		}
		const tool = event.toolName;
		const input = event.input as Record<string, unknown>;
		const nested = event.parentToolCallId !== undefined;

		// --- Fast path -----------------------------------------------------------------------
		if (READ_TOOLS.has(tool)) return undefined;
		const info = pi.getAllTools().find((t: any) => t.name === tool) as any;
		if (info?.annotations?.readOnlyHint === true && info.annotations.openWorldHint === false) return undefined;

		const transcript = readTranscript(ctx, event.parentToolCallId?.split("/")[0] ?? event.toolCallId);
		if (EDIT_TOOLS.has(tool) && !nested) {
			const size = writtenText(tool, input).length;
			const pending = backlog.reduce((n, id) => n + writtenTextOf(transcript, id).length, 0);
			// Next to a call that runs code, an edit is classified itself: all tool_call handlers of a batch run
			// before any tool does, so the other call's review would see the file as it was.
			const calmSiblings = (transcript.siblings ?? []).every((c) => READ_TOOLS.has(c.name) || EDIT_TOOLS.has(c.name));
			if (
				transcript.siblings !== undefined &&
				calmSiblings &&
				size <= MAX_FAST_EDIT &&
				pending + size <= MAX_BACKLOG &&
				isPlainProjectFile(input.path, ctx.cwd)
			) {
				backlog.push(event.toolCallId);
				return undefined;
			}
		}

		// --- Classify --------------------------------------------------------------------------
		const action = { tool, input };
		const actionText = json(action);
		const decide = (decision: Omit<LogEntry, "toolCallId" | "tool">) => log({ toolCallId: event.toolCallId, tool, ...decision });

		if (actionText.length > MAX_ACTION) {
			return block(ctx, decide, action, "is too large to review", undefined);
		}

		const { state, reviewed } = buildState(ctx, transcript, action, actionText, info, event.parentToolCallId);
		if (process.env.PI_SAFETY_DEBUG) appendFileSync(process.env.PI_SAFETY_DEBUG, `${json({ toolCallId: event.toolCallId, state })}\n`);
		const started = Date.now();
		checks++;
		let verdict: Verdict;
		try {
			const signals = [AbortSignal.timeout(config.timeoutMs), ctx.signal].filter(Boolean) as AbortSignal[];
			verdict = await classify(state, AbortSignal.any(signals));
		} catch (err) {
			if (ctx.signal?.aborted) return { block: true, reason: "The run was aborted." };
			const reason = `couldn't be reviewed (${clip((err as Error).message, 300)})`;
			if (config.onError === "allow") {
				decide({ decision: "allow", reason });
				updateStatus(ctx);
				return undefined;
			}
			if (ctx.hasUI) ctx.ui.notify(`pi-safety: ${reason}`, "warning");
			return block(ctx, decide, action, reason, { forceDeny: config.onError === "block" });
		}
		cost += verdict.cost;
		const ms = Date.now() - started;
		if (verdict.probability < config.threshold) {
			consecutiveDenials = 0;
			backlog = backlog.filter((id) => !reviewed.includes(id));
			decide({ decision: "allow", reviewedBacklog: true, probability: verdict.probability, category: verdict.category, model: verdict.model, ms });
			updateStatus(ctx);
			return undefined;
		}
		const reason = `looks ${CATEGORY_TEXT[verdict.category] ?? "risky"} (p=${verdict.probability.toFixed(2)})`;
		return block(ctx, decide, action, reason, undefined, verdict, ms);
	});

	/** The text an edit in the transcript wrote, for the backlog. */
	function writtenTextOf(transcript: Transcript, id: string): string {
		const call = transcript.byId.get(id);
		return call ? writtenText(call.name, call.arguments) : "";
	}

	function buildState(
		ctx: ExtensionContext,
		transcript: Transcript,
		action: { tool: string; input: Record<string, unknown> },
		actionText: string,
		info: any,
		parentToolCallId: string | undefined,
	): { state: Record<string, unknown>; reviewed: string[] } {
		let budget = MAX_TOTAL - actionText.length;
		const take = (text: string) => {
			budget -= text.length;
			return text;
		};

		// The user's first message is usually the task; keep it and the latest ones.
		const users = transcript.userMessages;
		const perUser = Math.max(500, Math.floor(Math.min(MAX_USER, budget) / Math.max(1, Math.min(users.length, 6))));
		const userMessages = [
			...(users.length > 6 ? [users[0], `[${users.length - 6} messages omitted]`] : []),
			...users.slice(users.length > 6 ? -5 : 0),
		].map((m) => take(clip(m, perUser)));

		const state: Record<string, unknown> = { cwd: ctx.cwd, user_messages: userMessages };

		if (!SHELL_TOOLS.has(action.tool) && !EDIT_TOOLS.has(action.tool) && action.tool !== "codemode" && info?.description) {
			state.tool_description = take(clip(String(info.description), 600));
		}
		state.action = action;

		if (parentToolCallId) {
			const parent = transcript.byId.get(parentToolCallId.split("/")[0]);
			if (parent) state.parent_action = take(clip(json({ tool: parent.name, input: parent.arguments }), 8_000));
		}

		// Everything the agent wrote through skipped edits, in full, so writing code and then running it is
		// reviewed. Only edits shown here count as reviewed.
		let reviewed: string[] = [];
		if (backlog.length) {
			const items = backlog.flatMap((id) => {
				const call = transcript.byId.get(id);
				return call ? [{ id, tool: call.name, path: call.arguments.path, text: writtenText(call.name, call.arguments) }] : [];
			});
			const { kept, dropped } = newestWithin(items, (i) => i.text.length + 100, Math.min(MAX_BACKLOG, budget));
			state.agent_written = kept.map((i) => ({ tool: i.tool, path: i.path, text: take(i.text) }));
			if (dropped) state.agent_written_omitted = `${dropped} older writes omitted`;
			reviewed = kept.map((i) => i.id);
		}

		// Skipped sibling edits are already in agent_written.
		if (transcript.siblings?.length) {
			const per = Math.max(1_000, Math.floor(MAX_SIBLINGS / transcript.siblings.length));
			state.same_turn_actions = transcript.siblings.map((c) =>
				backlog.includes(c.id)
					? { tool: c.name, path: c.arguments.path, see: "agent_written" }
					: take(clip(json({ tool: c.name, input: c.arguments }), per)),
			);
		}

		// Files the action runs, as they are now.
		if (EXEC_TOOLS.has(action.tool)) {
			const command = String(action.input.command ?? action.input.code ?? "");
			const files: Record<string, string> = {};
			let left = Math.min(MAX_FILES, budget);
			for (const path of referencedFiles(command, ctx.cwd)) {
				const text = readForReview(path);
				if (text === undefined || left < 500) continue;
				const clipped = clip(text, Math.min(MAX_FILE, left));
				files[relative(ctx.cwd, path)] = take(clipped);
				left -= clipped.length;
			}
			if (Object.keys(files).length) state.files = files;
		}

		const recent = transcript.earlierCalls.slice(-RECENT_ACTIONS).map((c) => clip(`${c.name} ${json(c.arguments)}`, 400));
		const { kept } = newestWithin(recent, (r) => r.length, Math.min(MAX_RECENT, Math.max(0, budget)));
		state.recent_actions = kept;
		if (denied.length) state.previously_blocked = denied.slice(-5);
		return { state, reviewed };
	}

	async function block(
		ctx: ExtensionContext,
		decide: (decision: Omit<LogEntry, "toolCallId" | "tool">) => void,
		action: { tool: string; input: Record<string, unknown> },
		reason: string,
		options: { forceDeny: boolean } | undefined,
		verdict?: Verdict,
		ms?: number,
	) {
		const details = { probability: verdict?.probability, category: verdict?.category, model: verdict?.model, ms, reason };
		// Only the TUI asks: an RPC client that doesn't answer dialogs would hang the run.
		if (config.ask && ctx.mode === "tui" && ctx.hasUI && !options?.forceDeny) {
			const preview = clip(action.tool === "bash" ? String(action.input.command) : json(action.input), 1_500);
			const choice = await ctx.ui.select(`🛡 pi-safety: this ${action.tool} call ${reason}.\n\n${preview}\n`, ["Block", "Allow once"]);
			if (choice === "Allow once") {
				consecutiveDenials = 0;
				decide({ decision: "ask-allow", ...details });
				return undefined;
			}
			decide({ decision: "ask-block", ...details });
			blocked++;
			updateStatus(ctx);
			return { block: true, reason: `The user declined this ${action.tool} call. Don't retry it or work around it; ask the user what to do instead.` };
		}

		blocked++;
		consecutiveDenials++;
		totalDenials++;
		denied.push({ tool: action.tool, input: clip(json(action.input), 400), reason });
		decide({ decision: "block", ...details });
		updateStatus(ctx);
		if (consecutiveDenials >= config.maxConsecutiveDenials || totalDenials >= config.maxDenials) {
			if (!stopped && ctx.hasUI) ctx.ui.notify(`pi-safety: stopping the run after ${totalDenials} blocked actions`, "error");
			stopped = true;
			try {
				ctx.abort();
			} catch {}
			return {
				block: true,
				terminate: true,
				reason: `Blocked by pi-safety: this action ${reason}. Too many actions were blocked, so the run is stopping. Explain to the user what you were trying to do and what needs their approval.`,
			};
		}
		return {
			block: true,
			reason: `Blocked by pi-safety: this action ${reason}${verdict ? ", and the user didn't ask for it" : ""}. Don't try to reach the same effect another way. Continue with the parts of the task that don't need it, or stop and tell the user what you need them to approve or run themselves.`,
		};
	}
}
