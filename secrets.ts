/**
 * Keeps secrets out of what the model's provider receives. Exfiltration is the classifier's job; this
 * is for when you don't trust what providers retain.
 *
 * Detection is redac---n's: token formats, private keys, credential names, secret files and commands
 * that print one (`cat .env`, `gh auth token`), encoded secrets, and random-looking tokens. What
 * pi-safety adds is what a library can't know:
 *
 * 1. Which files on this machine are secret: the project's `.env` files and credential files, the home
 *    directory's (`~/.aws/credentials`, pi's own auth.json), and the user's `secretPaths` globs. A read
 *    of one is redacted as a secret file, whatever its name says.
 * 2. Known values. Every credential in those files, and in credential-named environment variables, is
 *    taught to the Redactor and hidden wherever it appears, in every encoding. This is the guarantee:
 *    test/secrets-eval.ts requires zero leaks of known values. Plain words (`postgres`) can't be hidden
 *    everywhere without wrecking output, so only reads of the file hide those.
 * 3. Personal data people paste into chats (personal.ts), which redac---n leaves alone.
 */

import { readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { fromEnvironment, type Guessing, type Hint, isSecretFile, Redactor } from "redac---n";
import { redactPersonal } from "./personal.ts";

export type SecretsMode = "off" | "mask" | "block";

export interface SecretsConfig {
	mode: SecretsMode;
	/** How hard to guess at random-looking tokens with no name or format next to them (redac---n's `guessing`). */
	guessing?: Guessing;
	/** Extra secret files, as globs. A pattern without `/` matches file names. */
	paths: string[];
	/** Files that look secret but aren't, as globs. */
	notSecret: string[];
	/** pi's agent directory, whose auth files are secret. */
	agentDir: string;
}

// --- Which files are secret ------------------------------------------------------------------

/** `.crt`, `.cer`: secret only when they hold a private key, decided by content. */
const MAYBE_KEY = /\.(pem|crt|cer)$/i;
const PRIVATE_KEY_BEGIN = /-----BEGIN ([A-Z0-9 ]{0,40}PRIVATE KEY( BLOCK)?)-----/;
/** Paths under the home directory that hold credentials. A trailing / covers the whole tree. */
const HOME_SECRETS = [
	".ssh/",
	".aws/",
	".gnupg/",
	".azure/",
	".config/gcloud/",
	".kube/",
	".docker/config.json",
	".config/gh/hosts.yml",
	".config/hub",
	".config/rclone/",
	".config/sops/age/",
	".m2/settings.xml",
	".microsoft/usersecrets/",
	".gradle/gradle.properties",
	".cargo/credentials",
	".cargo/credentials.toml",
	".gem/credentials",
	".bundle/config",
	".mc/config.json",
	".doppler/",
	".supabase/access-token",
	".terraform.d/credentials.tfrc.json",
	".terraformrc",
	".vault-token",
	".claude/.credentials.json",
	".codex/auth.json",
	".local/share/opencode/auth.json",
];
const NOT_SECRET_IN_HOME = /^\.ssh\/(.*\.pub|known_hosts(\.old)?|authorized_keys|config)$|^\.aws\/cli\/|^\.config\/gcloud\/(logs|configurations)\/|^\.kube\/(cache|http-cache)\//;
const SKIP_DIRS = /^(node_modules|\.git|\.venv|venv|env|\.tox|\.nox|\.direnv|__pycache__|\.terraform|\.gradle|dist|build|target|\.next|\.cache|vendor|Pods)$/;

function globToRegex(glob: string): RegExp {
	let pattern = glob.startsWith("~/") ? join(homedir(), glob.slice(2)) : glob;
	const anchored = pattern.includes("/");
	pattern = pattern
		.replace(/[.+^${}()|[\]\\]/g, "\\$&")
		.replace(/\*\*\/?/g, "\u0000")
		.replace(/\*/g, "[^/]*")
		.replace(/\?/g, "[^/]")
		.replace(/\u0000/g, ".*");
	if (!anchored) return new RegExp(`(^|/)${pattern}$`);
	return new RegExp(isAbsolute(glob) || glob.startsWith("~/") ? `^${pattern}$` : `(^|/)${pattern}$`);
}

// --- Secrets ---------------------------------------------------------------------------------

interface FileEntry {
	mtimeMs: number;
	size: number;
}

export class Secrets {
	private config: SecretsConfig;
	private extra: RegExp[];
	private exempt: RegExp[];
	private home = homedir();
	private redactor: Redactor;
	private files = new Map<string, FileEntry>();
	private walkedAt = 0;
	private walkedCwd = "";
	/** Values taught from the environment. */
	private environment = new Set<string>();
	/** Bumped whenever the set of known values may have grown, so cached redactions can be reused until then. */
	version = 0;

	constructor(config: SecretsConfig) {
		this.config = config;
		this.extra = config.paths.map(globToRegex);
		this.exempt = config.notSecret.map(globToRegex);
		this.redactor = new Redactor({ guessing: config.guessing });
	}

	get mode(): SecretsMode {
		return this.config.mode;
	}

	/** Whether `path` (absolute) is a secret file, by its own path or the one it links to. */
	isSecret(path: string): boolean {
		if (this.matches(path)) return true;
		try {
			const real = realpathSync(path);
			return real !== path && this.matches(real);
		} catch {
			return false;
		}
	}

	/** Whether a path could be a secret file, judged by name alone, without touching the disk. */
	private mightBeSecret(path: string): boolean {
		return this.extra.some((r) => r.test(path)) || isSecretFile(path) || MAYBE_KEY.test(path) || path.startsWith(this.home);
	}

	private matches(path: string): boolean {
		if (this.exempt.some((r) => r.test(path))) return false;
		if (this.extra.some((r) => r.test(path)) || isSecretFile(path)) return true;
		if (path.endsWith(".pub")) return false;
		if (MAYBE_KEY.test(path)) return holdsPrivateKey(path);
		if (path === join(this.config.agentDir, "auth.json") || path === join(this.config.agentDir, "mcp-auth.json")) return true;
		const rel = relative(this.home, path).split(sep).join("/");
		if (rel.startsWith("..") || isAbsolute(rel)) return false;
		return HOME_SECRETS.some((s) => (s.endsWith("/") ? rel.startsWith(s) : rel === s)) && !NOT_SECRET_IN_HOME.test(rel);
	}

	/**
	 * What the model gets instead of a tool's text output. `hint` says where it came from: the file a
	 * read returned (`secretFile` when that file is secret by pi-safety's rules), or the shell command
	 * that printed it. The extension and the test harness both go through here.
	 */
	scrub(text: string, cwd: string, hint: Hint = {}): string {
		this.refresh(cwd);
		// UTF-16 text read as UTF-8 has a NUL after every character.
		if ((text.match(/\0/g)?.length ?? 0) > text.length * 0.25) text = text.replace(/\0/g, "");
		const redacted = this.redactor.redact(text, { hint }).text;
		// What it found here is hidden everywhere from now on, earlier messages included. (After the
		// redaction, which it would otherwise run again: learning changes the known values.)
		if (this.redactor.learn(text, { hint })) this.version++;
		return this.redactPersonal(redacted);
	}

	/** Replaces known values and whatever redac---n recognizes, for text with no file or command behind it. */
	redact(text: string): string {
		return this.redactPersonal(this.redactor.redact(text).text);
	}

	private redactPersonal(text: string): string {
		return redactPersonal(text, (kind, value) => `[REDACTED ${kind} #${this.redactor.fingerprint(value)}]`);
	}

	/** Forgets the directory walk, so a secret file just written is picked up at the next refresh. */
	invalidate() {
		this.walkedAt = 0;
	}

	/**
	 * Brings the known values up to date: re-reads changed secret files and the environment, and re-walks
	 * the project for new files at most every 30 seconds (or right after `invalidate`). Values are only
	 * ever added: one taken out of a file was still a secret.
	 */
	refresh(cwd: string) {
		if (cwd !== this.walkedCwd || Date.now() - this.walkedAt > 30_000) {
			const paths = new Set([...this.projectSecretFiles(cwd), ...this.homeSecretFiles()]);
			for (const path of this.files.keys()) if (!paths.has(path)) this.files.delete(path);
			for (const path of paths) if (!this.files.has(path)) this.files.set(path, { mtimeMs: -1, size: -1 });
			for (const { value, label } of fromEnvironment(process.env)) {
				// The Redactor's addKnown is true for a value it already held too.
				if (!this.environment.has(value) && this.redactor.addKnown(value, label)) {
					this.environment.add(value);
					this.version++;
				}
			}
			this.walkedCwd = cwd;
			this.walkedAt = Date.now();
		}
		for (const [path, entry] of this.files) {
			let stat: import("node:fs").Stats | undefined;
			try {
				stat = statSync(path);
			} catch {}
			const mtimeMs = stat?.mtimeMs ?? 0;
			const size = stat?.size ?? 0;
			if (mtimeMs === entry.mtimeMs && size === entry.size) continue;
			this.files.set(path, { mtimeMs, size });
			if (stat?.isFile()) this.learnFile(path);
		}
	}


	/** Teaches the Redactor the secrets in a file, except guesses, which are hidden only where they are. */
	private learnFile(path: string) {
		let text: string;
		try {
			if (statSync(path).size > 32 * 1024 * 1024) return;
			text = readFileSync(path, "utf8");
		} catch {
			return;
		}
		if ((text.match(/\0/g)?.length ?? 0) > text.length * 0.25) text = text.replace(/\0/g, "");
		if (this.redactor.learn(text, { hint: { path, secretFile: true } })) this.version++;
	}

	private projectSecretFiles(cwd: string): string[] {
		const out: string[] = [];
		let visited = 0;
		const walk = (dir: string, depth: number) => {
			let entries: import("node:fs").Dirent[];
			try {
				entries = readdirSync(dir, { withFileTypes: true });
			} catch {
				return;
			}
			for (const entry of entries) {
				if (++visited > 200_000 || out.length >= 5_000) return;
				const path = join(dir, entry.name);
				if (entry.isDirectory()) {
					if (depth < 16 && !SKIP_DIRS.test(entry.name)) walk(path, depth + 1);
				} else if ((this.mightBeSecret(path) && this.isSecret(path)) || (/\.ya?ml$/.test(entry.name) && isKubeSecret(path))) out.push(path);
			}
		};
		// A cwd of ~ or / would walk the whole disk; home credentials are listed separately.
		if (resolve(cwd) !== this.home && resolve(cwd) !== resolve("/")) walk(cwd, 0);
		return out;
	}

	private homeSecretFiles(): string[] {
		const out = [join(this.config.agentDir, "auth.json"), join(this.config.agentDir, "mcp-auth.json")];
		const walk = (dir: string, depth: number) => {
			let names: string[];
			try {
				names = readdirSync(dir);
			} catch {
				return;
			}
			for (const name of names) {
				const path = join(dir, name);
				let isDir = false;
				try {
					isDir = statSync(path).isDirectory();
				} catch {}
				if (isDir) {
					if (depth < 4) walk(path, depth + 1);
				} else if (this.isSecret(path)) out.push(path);
			}
		};
		for (const entry of HOME_SECRETS) {
			if (entry.endsWith("/")) walk(join(this.home, entry), 0);
			else out.push(join(this.home, entry));
		}
		for (const name of [".netrc", ".npmrc", ".pypirc", ".git-credentials", ".env", ".pgpass", ".my.cnf", ".s3cfg", ".boto"]) out.push(join(this.home, name));
		return out;
	}
}

function holdsPrivateKey(path: string): boolean {
	try {
		if (statSync(path).size > 256 * 1024) return false;
		return PRIVATE_KEY_BEGIN.test(readFileSync(path, "utf8"));
	} catch {
		return false;
	}
}

function isKubeSecret(path: string): boolean {
	try {
		if (statSync(path).size > 32 * 1024 * 1024) return false;
		return /^kind:[ \t]*Secret\b/m.test(readFileSync(path, "utf8"));
	} catch {
		return false;
	}
}
