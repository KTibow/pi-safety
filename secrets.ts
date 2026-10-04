/**
 * Keeps secrets out of what the model's provider receives. Exfiltration is the classifier's job; this
 * is for when you don't trust what providers retain.
 *
 * Three layers, applied to every tool result (and, through the `context` hook, everything else):
 *
 * 1. Masking. A read of a secret file, a command that prints one (`cat .env`), and grep lines from one
 *    show the file with credential values replaced by `[secret]`. Whether a value is a credential is
 *    decided by its name's last word, the word that says what the value is: `DB_PASSWORD` and
 *    `client-key-data` hold credentials, `PASSWORD_MIN_LENGTH` and `TOKEN_URL` don't. Under any other
 *    name, only random-looking tokens and known token formats are hidden.
 * 2. Known values. Credentials found in secret files under the project, credential files in the home
 *    directory, and credential-named environment variables are replaced wherever they appear, also
 *    JSON-, URL-, shell- and hex-encoded, and inside base64 or hex blobs. This is the guarantee:
 *    test/secrets-eval.ts requires zero leaks of known values. Plain words (`postgres`) can't be
 *    replaced everywhere without wrecking output, so only masking hides them.
 * 3. Patterns, for secrets that were never in a file: well-known token formats, private keys, URL
 *    passwords, Authorization headers, and credential-named values (`password=…`, `"token": "…"`,
 *    `--api-key …`) whose value also looks like a secret, and personal data people paste into chats:
 *    SSNs, cards, PINs, recovery phrases and codes, one-time sign-in links. This layer is best effort.
 *
 * Every regex here runs on untrusted output, so each is linear: bounded repetition, no `\s` across lines.
 */

import { createHash } from "node:crypto";
import { readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { BIP39_WORDS } from "./bip39.ts";

export type SecretsMode = "off" | "mask" | "block";

export interface SecretsConfig {
	mode: SecretsMode;
	/** "precise" (default): only unmistakable patterns in ordinary output. "broad": also credential-named values. */
	patterns?: "precise" | "broad";
	/** Extra secret files, as globs. A pattern without `/` matches file names. */
	paths: string[];
	/** Files that look secret but aren't, as globs. */
	notSecret: string[];
	/** pi's agent directory, whose auth files are secret. */
	agentDir: string;
}

// --- Names ----------------------------------------------------------------------------------

/** Words that, as the last word of a name, say the value is a credential. */
const CREDENTIAL_WORDS = new Set([
	"KEY", "APIKEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PASS", "PWD", "PW", "PASSPHRASE",
	"CREDENTIAL", "CREDENTIALS", "COOKIE", "PAT", "AUTH", "SALT", "SIG", "SIGNATURE", "PIN", "REQUIREPASS",
	"SID", "SESSIONID", "SESSID", "MNEMONIC", "SEED", "PHRASE", "PASSCODE", "PSK",
]);
/** Single words that end in a credential word: PGPASSWORD, AUTHKEY, WRITEKEY. */
const CREDENTIAL_SUFFIX = /(PASSWORD|PASSWD|PASSPHRASE|PASSCODE|TOKEN|SECRET|APIKEY|AUTH|AUTHKEY|WRITEKEY|SECRETKEY|PRIVATEKEY|ACCESSKEY|SESSID|SESSIONID|PASS)$/;
/** Last words that describe a form of the word before: `client-key-data`, `SECRET_B64`, `secret_key_base`. */
const WRAPPER_WORDS = new Set(["DATA", "VALUE", "B64", "BASE64", "ENC", "ENCODED", "RAW", "HEX", "BASE", "STRING"]);
/** Last words that only qualify the word before: `API_KEY_V2`, `DB_PASSWORD_PROD`, `KEYS`. */
const QUALIFIER_WORDS = /^(V\d+|\d+|PROD|PRODUCTION|DEV|DEVELOPMENT|STAGING|STAGE|TEST|LIVE|OLD|NEW|PREVIOUS|PREV|CURRENT|NEXT_?|PRIMARY|SECONDARY|BACKUP|FALLBACKS?|ROTATED|LOCAL|REMOTE|DEFAULT)$/;
/** Words before a credential word that make it something public or not a credential at all, per credential word. */
const NOT_CREDENTIAL_BEFORE: Record<string, Set<string>> = {
	KEY: new Set([
		"PUBLIC", "PUBLISHABLE", "SITE", "GPG", "PARTITION", "SORT", "HASH", "RANGE", "FOREIGN", "CACHE",
		"IDEMPOTENCY", "OBJECT", "TOPOLOGY", "SEARCH", "SORTING", "MAP", "SSH",
	]),
	TOKEN: new Set(["NEXT", "PAGE", "CONTINUATION", "CURSOR", "SYNC", "RESUME", "CSRF", "XSRF", "PAGINATION", "MAX", "MIN", "NUM", "COUNT"]),
	SID: new Set(["ORACLE", "DB", "DATABASE", "SERVICE"]),
	ID: new Set([]),
	SECRET: new Set(["EXISTING", "EXTERNAL"]),
};
/** Words that say a value identifies or locates something, so it isn't a secret even if it looks random. */
const IDENTIFIER_WORDS = new Set([
	"ID", "IDS", "ARN", "URL", "URI", "HOST", "HOSTNAME", "DOMAIN", "NAME", "REGION", "ZONE", "BUCKET", "PRICE", "PRODUCT",
	"PLAN", "SKU", "ENDPOINT", "PATH", "DIR", "FILE", "EMAIL", "USER", "USERNAME", "PORT", "VERSION", "TAG", "SHA", "PUBLIC",
	"PUBLISHABLE", "SITE", "PROJECT", "ACCOUNT", "TENANT", "ORG", "TEAM", "CHANNEL", "STYLE", "LOCALE",
]);
/** Prefixes of variables that frameworks expose to the browser, so they're public by design. */
const PUBLIC_PREFIX = /^(NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|PUBLIC|NUXT_PUBLIC|GATSBY)_/i;
/** Shell variables whose names end in a credential word but hold something else. */
const NOT_CREDENTIAL_NAMES = new Set(["PWD", "OLDPWD"]);

function words(name: string): string[] {
	return name
		.replace(/([a-z0-9])([A-Z])/g, "$1_$2")
		.toUpperCase()
		.split(/[^A-Z0-9]+/)
		.filter(Boolean);
}

/**
 * Whether a name holds a credential only when its value looks like one: a webhook URL (an internal
 * `https://hooks.acme.io/t/2` is harmless, one ending in a long random token is a bearer secret) and a
 * session id (`TERM_SESSION_ID` is a terminal's, `INSTAGRAM_SESSION_ID` is a live login).
 */
function isCredentialWhenRandom(name: string): boolean {
	const w = words(name);
	return w.includes("WEBHOOK") || (w.at(-1) === "ID" && w.includes("SESSION"));
}

/** Whether a value contains something that looks randomly generated, rather than a name or a UUID. */
function hasRandomToken(value: string): boolean {
	return (value.match(/[A-Za-z0-9+/=_-]{16,4096}/g) ?? []).some(isRandomToken);
}

/** Whether a name's value is a credential, judged by the name's last meaningful word. */
export function isCredentialName(name: string): boolean {
	if (NOT_CREDENTIAL_NAMES.has(name) || PUBLIC_PREFIX.test(name) || /^applicationServerKey$/i.test(name)) return false;

	const w = words(name);
	while (w.length > 1 && (WRAPPER_WORDS.has(w.at(-1)!) || QUALIFIER_WORDS.test(w.at(-1)!))) w.pop();
	let last = w.at(-1);
	if (last === undefined) return false;

	last = last.replace(/(?<=[A-Z])\d+$/, "").replace(/(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)S$/, "$1");
	if (!CREDENTIAL_WORDS.has(last) && !CREDENTIAL_SUFFIX.test(last)) return false;
	if (w.length > 1 && NOT_CREDENTIAL_BEFORE[last]?.has(w.at(-2)!)) return false;
	return true;
}

// --- Values ---------------------------------------------------------------------------------

function entropy(value: string): number {
	const counts = new Map<string, number>();
	for (const c of value) counts.set(c, (counts.get(c) ?? 0) + 1);
	let bits = 0;
	for (const n of counts.values()) bits -= (n / value.length) * Math.log2(n / value.length);
	return bits;
}

/**
 * Words, short numbers and short IDs joined by separators: names like `acme-prod-uploads-2024`,
 * `refs/pull/482/merge` or `--max-old-space-size=4096`, not keys.
 */
function isWordy(value: string): boolean {
	return value
		.split(/[-_./=+:,@ !?]+/)
		.every((part) => part === "" || /^\p{L}+\d{0,4}$/u.test(part) || /^\d{1,6}$/.test(part) || /^[0-9a-f]{1,12}$/i.test(part));
}

/** A value that can't be a credential: empty, a boolean, a path, a placeholder or a reference to one held elsewhere. */
function isInert(value: string): boolean {
	return (
		value === "" ||
		/^(true|false|null|none|nil|undefined|yes|no|on|off|inherit|required|optional)$/i.test(value) ||
		isPath(value) ||
		/^\$\{?[\w.-]{1,80}(:[-?][^}]{0,80})?\}?$/.test(value) ||
		/^<%=?[^%]{0,200}%>$|^#\{[^}]{0,200}\}$|^@[\w.-]{1,80}@$/.test(value) ||
		/^age1[0-9a-z]{58}$/.test(value) ||
		/^%\w+%$|\{\{.{0,200}\}\}|^\$\(|^<[\w .-]+>$|\.\.\.|…|change[-_ ]?me|^x{3,}$|^\*+$|^redacted$/i.test(value) ||
		(/^(your|my|example|sample|dummy|fake|placeholder|replace)[-_ ]/i.test(value) && isWordy(value))
	);
}

/** A file path: path-shaped, with no segment that looks like a random key. */
function isPath(value: string): boolean {
	if (!/^(\.{1,2}\/|~\/|\/|\$\{?HOME\}?\/)[\w.\-/+@${}]+$/.test(value) || !value.slice(1).includes("/")) return false;
	return value.split("/").every((seg) => !(seg.length >= 12 && /[a-z]/.test(seg) && /[A-Z]/.test(seg) && /\d/.test(seg)));
}

/** A token that looks randomly generated: a key, not a name, hash or ID. */
function isRandomToken(token: string): boolean {
	if (token.length < 16 || token.length > 4_096 || !/^[A-Za-z0-9+/=_-]+$/.test(token) || !/[A-Za-z]/.test(token)) return false;
	if (/^[0-9a-f]+$/i.test(token) || /^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(token) || isWordy(token)) return false;
	if (/^[0-7][0-9A-HJKMNP-TV-Z]{25}$/.test(token) || /^c[a-z0-9]{24,32}$/.test(token)) return false; // ULID, cuid
	if (!/\d/.test(token)) {
		// Letters only: random only if long and the case flips constantly (not camelCase words).
		const flips = token.match(/[a-z][A-Z]|[A-Z][a-z]/g)?.length ?? 0;
		return token.length >= 24 && flips >= token.length * 0.35 && entropy(token) >= 4;
	}
	return entropy(token) >= 3.5;
}

/**
 * Whether a credential value is distinctive enough to replace wherever it appears, or to mask in
 * arbitrary output. Plain words and very short values would also match ordinary text.
 */
function isDistinctive(value: string): boolean {
	if (value.length < 6 || value.length > 8_192 || isInert(value)) return false;
	// A plain word is replaceable only if it's long and not a stock default that appears in ordinary output.
	if (/^\p{L}+$/u.test(value)) return value.length >= 14 && !COMMON_WORDS.has(value.toLowerCase());
	if (/^\d{1,8}$/.test(value)) return false;
	if (/^[a-z][a-z0-9+.-]*:\/\/[^@\s]*$/i.test(value) || /^[\w.-]+@[\w.-]+\.\w+$/.test(value)) return false; // URLs without credentials, emails
	return !isWordy(value) || value.length >= 20 || isMadePassword(value) || /[-_ ]/.test(value) || (/\d/.test(value) && /\p{L}/u.test(value));
}

/** Default passwords and words that show up in ordinary output, so they can't be replaced everywhere. */
const COMMON_WORDS = new Set([
	"password", "passwords", "passwd", "postgres", "postgresql", "database", "changeme", "secret", "secrets", "admin",
	"administrator", "example", "mariadb", "mongodb", "default", "development", "production", "staging", "localhost",
	"testing", "letmein", "welcome", "superuser", "sqlserver", "rabbitmq", "minioadmin", "keycloak", "elastic", "grafana",
	"jenkins", "vagrant", "password", "username", "anonymous", "readonly", "readwrite", "internal", "external", "sandbox",
]);

/** A placeholder such as `sk_test_xxxxxxxx` or `ghp_0000…`: mostly one repeated character. */
function isPlaceholder(token: string): boolean {
	const counts = new Map<string, number>();
	for (const c of token) counts.set(c, (counts.get(c) ?? 0) + 1);
	return [...counts.values()].some((n) => n >= 6 && n >= token.length * 0.5);
}

/** Replaces well-known token formats, except placeholders. */
function redactFormats(text: string, label: (name: string) => string): string {
	for (const [name, pattern] of TOKEN_FORMATS) {
		text = text.replace(pattern, (m) => (isPlaceholder(m) ? m : label(name)));
	}
	return text;
}

/** An SSH public key, which is published by design. */
const SSH_PUBLIC_KEY = /\b(ssh-(rsa|dss|ed25519|ed448)|ecdsa-sha2-nistp\d{3}|sk-(ssh|ecdsa)[\w@.-]*)[ \t]+[A-Za-z0-9+/]{32,}={0,3}/;

/** Strips quotes, a trailing comma or semicolon, and an inline comment from a raw value. */
function cleanValue(raw: string): string {
	const value = raw.trim().replace(/[,;]$/, "").trim();
	const quoted = value.match(/^(["'`])(.*?)\1(?:\s+#.*)?$/s);
	if (quoted) return quoted[2].replace(/\\(["'\\])/g, "$1");
	return value.replace(/\s+#.*$/, "").trim();
}

/** Code rather than a literal value: an environment lookup, a call, a variable. Quoted strings are literals. */
function isCode(raw: string): boolean {
	if (/^["'`]/.test(raw.trim())) return false;
	return /[(){}[\]]|process\.env|os\.environ|getenv|ENV\[|^\$\w|^\$\{|^env\.|^config\.|^settings\./.test(raw);
}

/** Words with capitals and digits mixed in, the way people make passwords: `Maple-Orbit-42`, `Harvest2025`. */
function isMadePassword(value: string): boolean {
	return /[a-z]/.test(value) && /[A-Z]/.test(value) && /\d/.test(value);
}

/**
 * A credential-named value in arbitrary output that should be masked: not a plain word, type, label,
 * lowercase identifier, path, placeholder or code.
 */
function looksSecret(raw: string): boolean {
	const v = cleanValue(raw);
	if (v.length < 6 || v.length > 8_192 || isInert(v) || isCode(raw)) return false;
	if (/^\p{L}{1,12}[!?]?$/u.test(v) || /^\d{1,8}$/.test(v)) return false;
	if (/^[a-z][a-z0-9+.-]*:\/\/[^@\s]*$/i.test(v) || /^[\w.-]+@[\w.-]+\.\w+$/.test(v)) return false;
	// Groups of capitals and digits: recovery and license keys like `A3-ABC123-DEF456-…`.
	const mixedGroups = v.split("-").filter((g) => /\d/.test(g) && /[A-Z]/.test(g)).length;
	return !isWordy(v) || isMadePassword(v) || (/^[A-Z0-9]{2,8}(-[A-Z0-9]{4,8}){3,}$/.test(v) && mixedGroups >= 2);
}

// --- Patterns found in any output ----------------------------------------------------------------

/** Well-known token formats (from gitleaks, pi-redact and the providers' docs). */
const TOKEN_FORMATS: [string, RegExp][] = [
	["AWS key", /\b(AKIA|ASIA)[A-Z0-9]{16}\b/g],
	["GitHub token", /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g],
	["GitLab token", /\bgl(pat|dt|ptt|rt|soat|cbt|imt)-[A-Za-z0-9_-]{20,}/g],
	["API key", /\bsk-(ant-|proj-|or-v1-|svcacct-)?[A-Za-z0-9_-]{20,}/g],
	["Stripe key", /\b(sk|rk)_(live|test)_[A-Za-z0-9]{20,}\b/g],
	["Stripe webhook secret", /\bwhsec_[A-Za-z0-9+/=]{20,}/g],
	["Slack token", /\bxox[abposr]-[A-Za-z0-9-]{20,}|\bxapp-\d-[A-Za-z0-9-]{20,}/g],
	["Slack webhook", /(?<=https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/)[A-Za-z0-9/_-]{20,}/g],
	["Discord webhook", /(?<=https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{5,30}\/)[A-Za-z0-9_-]{40,}/g],
	["Google API key", /\bAIza[A-Za-z0-9_-]{35}\b/g],
	["Google OAuth token", /\bya29\.[A-Za-z0-9_-]{20,}|\b1\/\/0[A-Za-z0-9_-]{30,}/g],
	["npm token", /\bnpm_[A-Za-z0-9]{36,}\b/g],
	["PyPI token", /\bpypi-AgE[A-Za-z0-9_-]{50,}/g],
	["Docker token", /\bdckr_pat_[A-Za-z0-9_-]{20,}/g],
	["DigitalOcean token", /\bdo[opr]_v1_[a-f0-9]{64}\b/g],
	["Hugging Face token", /\bhf_[A-Za-z0-9]{30,}\b/g],
	["Shopify token", /\bshp(at|ss|ca|pa)_[a-fA-F0-9]{32}\b/g],
	["Grafana token", /\bgl(sa|c)_[A-Za-z0-9+/=_]{32,}/g],
	["Vault token", /\bhv[sbr]\.[A-Za-z0-9_-]{20,}/g],
	["age key", /\bAGE-SECRET-KEY-1[0-9A-Z]{58}\b/g],
	["Supabase key", /\bsb(p|_secret)_[A-Za-z0-9_-]{20,}/g],
	["Doppler token", /\bdp\.(st|ct|sa|scim|audit|pt)\.[A-Za-z0-9._-]{30,}/g],
	["Tailscale key", /\btskey-(auth|api|client|scim|webhook)-[A-Za-z0-9-]{20,}/g],
	["Honeycomb key", /\bhcaik_[A-Za-z0-9]{40,}/g],
	["Netlify token", /\bnfp_[A-Za-z0-9]{36,}/g],
	["Linear key", /\blin_api_[A-Za-z0-9]{30,}/g],
	["Postman key", /\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b/g],
	["Atlassian token", /\bATATT3[A-Za-z0-9_=-]{100,}/g],
	["1Password token", /\bops_eyJ[A-Za-z0-9_-]{50,}/g],
	["Fly.io token", /\bfm[12]_[A-Za-z0-9+/=_-]{50,}/g],
	["Mailgun key", /\bkey-[0-9a-f]{32}\b/g],
	["SendGrid key", /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{32,}/g],
	["Telegram bot token", /\b\d{8,10}:AA[A-Za-z0-9_-]{33}(?![\w-])/g],
	["Discord bot token", /\b[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}(?![\w-])/g],
	["Notion token", /\bntn_[A-Za-z0-9]{40,}\b|\bsecret_[A-Za-z0-9]{43}\b/g],
	["Venice key", /\bVENICE_INFERENCE_KEY_(?=[A-Za-z_-]{0,40}\d)[A-Za-z0-9_-]{20,}/g],
	// The `<vendor>_sk_` convention: `aria_sk_…`, ElevenLabs' `sk_…`.
	["API key", /\b(?:[a-z][a-z0-9]{1,15}_)?sk_(?!live_|test_)(?=[A-Za-z]{0,40}\d)[A-Za-z0-9]{24,}\b/g],
	["JWT", /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g],
];

const PRIVATE_KEY_BEGIN = /-----BEGIN ([A-Z0-9 ]{0,40}PRIVATE KEY( BLOCK)?)-----/;
/** A line of key material, possibly after a grep (`path-12-`) or diff (`+`, `-`) prefix, or inside a string. */
const KEY_BODY_LINE = /^(?:[^\s:]{1,300}[:-]\d{1,9}[:-]|[+-]|[ \t>"']{1,20})?[ \t]{0,20}(?:[A-Za-z0-9+/=]{4,}|[A-Za-z-]{1,40}: .{0,200}|)[ \t"',]{0,4}\r?$/;

/**
 * Replaces private key blocks: the BEGIN line through the END line, or through the last line of key
 * material when output stops early. A BEGIN line with no key material after it, like a string
 * constant in source code, is left alone. Handles real newlines and `\n`/`\r\n` escapes (keys in JSON),
 * and `openssl pkey -text` output.
 */
function redactPrivateKeys(text: string, replacement: string): string {
	if (!text.includes("PRIVATE KEY") && !/priv|prime|exponent|coefficient/i.test(text)) return text;
	text = text.replace(
		/-----BEGIN ([A-Z0-9 ]{0,40}PRIVATE KEY( BLOCK)?)-----(?:(?:\\r)?\\n[A-Za-z0-9+/=: ,_-]{0,200}){1,500}?(?:(?:\\r)?\\n)?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY( BLOCK)?-----|(?=["']|$))/g,
		replacement,
	);
	text = text.replace(
		/^([ \t]{0,20}(?:priv(?:ate)?(?:[- ]?key)?|privateExponent|prime[12]|exponent[12]|coefficient)[ \t]{0,20}:[ \t]{0,20}\r?\n)((?:[ \t]{1,20}(?:[0-9a-f]{2}:){1,40}[0-9a-f]{0,2}[ \t]{0,20}(?:\r?\n|$)){1,200})/gim,
		(_m, head) => `${head}    ${replacement}\n`,
	);
	if (!text.includes("PRIVATE KEY")) return text;
	const lines = text.split("\n");
	for (let i = 0; i < lines.length; i++) {
		if (!PRIVATE_KEY_BEGIN.test(lines[i])) continue;
		let j = i + 1;
		while (j < lines.length && j - i < 600 && KEY_BODY_LINE.test(lines[j]) && !/-----END/.test(lines[j])) j++;
		const ended = j < lines.length && /^[^\w]{0,20}-----END [A-Z0-9 ]{0,40}PRIVATE KEY( BLOCK)?-----[^\w]{0,20}\r?$/.test(lines[j]);
		// Source code that only names the armor has no key material between BEGIN and END.
		const material = lines.slice(i + 1, j).some((l) => /[A-Za-z0-9+/=]{24,}/.test(l));
		if (!material) continue;
		const prefix = lines[i].slice(0, lines[i].search(/-----BEGIN/));
		const suffix = ended ? lines[j].slice(lines[j].search(/-----[ \t"',]*\r?$/) + 5) : "";
		lines.splice(i, (ended ? j + 1 : j) - i, `${prefix}${replacement}${suffix}`);
	}
	return lines.join("\n");
}

/**
 * The patterns that are credentials wherever they appear, so they're safe to apply to any output:
 * Authorization headers, Bearer/Basic tokens, URL passwords, cookie values, and AWS credentials in
 * `--output text`. Credential-named values (`password=…`) need the "broad" patterns.
 */
function redactUnmistakable(text: string): string {
	if (!/auth|bearer|basic|:\/\/|cookie|CREDENTIALS\t/i.test(text)) return text;
	// Docs and changelogs quote headers, so strip the quoting before deciding whether a value is real.
	const literal = (raw: string) => {
		const value = raw.replace(/^[`'"(\[]+|[`'")\].,;:]+$/g, "");
		return value !== "" && !isInert(value) && !isCode(value) && !isPlaceholder(value) && !/^%[\w.-]{1,80}%$/.test(value) && !/^[A-Z][A-Z0-9_]{2,}$/.test(value);
	};
	return text
		.split("\n")
		.map((line) => {
			if (line.length > 20_000) return line;
			line = line
				.replace(/(\bAuthorization["']?[ \t]{0,10}[:=][ \t]{0,10}["']?(?:Bearer|Basic|Token|Bot|Digest|ApiKey|SSWS|token|bearer|basic)[ \t]{1,10})([^\s"',;]{1,2000})/gi, (m, head, value) =>
					literal(value) ? `${head}[secret]` : m,
				)
				.replace(/\b(Bearer|Basic)([ \t]{1,10})([A-Za-z0-9._~+/-]{16,2000}={0,2})/g, (m, scheme, gap, value) =>
					literal(value) && !isPlaceholder(value) ? `${scheme}${gap}[secret]` : m,
				)
				.replace(/\b([a-z][a-z0-9+.-]{0,20}:\/\/[^\s/?#@:]{0,200}:)([^\s]{1,300}?)(@[^\s@/?#"']{1,300}(?=[/?#:\s"']|$))/gi, (m, head, pw, tail) =>
					isUrlPassword(pw) ? `${head}[secret]${tail}` : m,
				)
				.replace(/^(CREDENTIALS\t[^\t]{1,200}\t[^\t]{1,200}\t)([^\t]{1,200})(\t)(.{1,4000})$/, "$1[secret]$3[secret]")
				// A credential in a URL's query string: `?apikey=…`, `&sig=…`.
				.replace(/([?&])([\w.-]{1,60})=([^&\s"'#<>]{1,500})/g, (m, sepr, name, value) =>
					isCredentialName(name) && literal(value) ? `${sepr}${name}=[secret]` : m,
				);
			return line.replace(/^([ \t]{0,10}(?:< |> )?(?:set-)?cookie:[ \t]{0,10})(.{1,4000})$/i, (_m, head, cookies) =>
				head +
				cookies.replace(/(^|;[ \t]{0,5})([^=;\s]{1,100})=([^;]{0,2000})/g, (m: string, sepr: string, name: string) =>
					/^(domain|path|expires|max-age|samesite|secure|httponly|priority|partitioned)$/i.test(name) ? m : `${sepr}${name}=[secret]`,
				),
			);
		})
		.join("\n");
}

/**
 * Whether a URL's password field holds a password, rather than a variable, a format specifier
 * (`%s`, `{password}`, `$1`) or a placeholder, as in the DSN builders and docs agents read all day.
 */
function isUrlPassword(value: string): boolean {
	if (!value || isInert(value) || isPlaceholder(value)) return false;
	if (/^[A-Z_][A-Z0-9_]*$/.test(value) || /^\$|\$\{|\{\{|%[sdv]|\{[\w.-]{1,60}\}|<[\w .-]{1,60}>|\(|\)/.test(value)) return false;
	return !/^(user|username|pass|password|passwd|pwd|secret|token|credentials)$/i.test(value);
}

/** Path segments of one-time links: `/reset/<token>`, `/auth/magic-link/<token>`, `/verify-email/<token>`. */
const SIGN_IN_SEGMENT = /^(?:(?:password|email|account|user|magic)[-_]?)?(?:reset|verify|verification|confirm|confirmation|magic|login|signin|sign[-_]in|activate|activation|invite|invitation|unlock|recover|recovery|otp|claim|passwordless|onetime|one[-_]time)(?:[-_]?(?:password|email|account|links?|tokens?|login))?$/i;
/** Query parameters that carry a one-time login: OAuth and Firebase codes, CAS tickets. */
const SIGN_IN_PARAM = /^(code|oobcode|otp|ticket)$/i;

/**
 * Reset, magic sign-in and verification links, which log in whoever opens them: a random token in the
 * path after `/reset/`, `/magic-link/`, `/verify/`, or in the query as `?code=`. Emails are full of them.
 */
function redactSignInLinks(text: string): string {
	if (!/https?:\/\//i.test(text)) return text;
	return text.replace(/\bhttps?:\/\/[^\s"'<>`)\]]{1,2000}/gi, (url) => {
		const q = url.search(/[?#]/);
		const segments = (q < 0 ? url : url.slice(0, q)).split("/");
		const at = segments.findIndex((s, i) => i >= 3 && SIGN_IN_SEGMENT.test(s));
		// Laravel and Django reset tokens are hex, but so are commit hashes, so hex counts only right after the keyword.
		const path = segments.map((s, i) => (at >= 0 && i > at && (isRandomToken(s) || (i === at + 1 && /^[0-9a-f]{32,}$/i.test(s))) ? "[secret]" : s)).join("/");
		const query = (q < 0 ? "" : url.slice(q)).replace(/([?&#])([\w.-]{1,60})=([^&#]{1,1000})/g, (m, sepr, name, value) =>
			(at >= 0 || SIGN_IN_PARAM.test(name)) && !/^utm_/i.test(name) && isRandomToken(value) ? `${sepr}${name}=[secret]` : m,
		);
		return path + query;
	});
}

// --- Personal data ---------------------------------------------------------------------------
//
// Identity numbers, payment cards, door codes and account recovery material, which people paste into
// chats and which arrive in emails. None of it is ever in a .env, so only patterns catch it. A bare
// number is hidden only when a checksum or the issuing rules confirm it; after a label (`SSN:`, `card
// number`) a mistyped one is hidden too, since 15 right digits of a card still leak it. Published
// test numbers and examples stay, because tests and docs need them.

/** Spaces, including the no-break space that forms and PDFs paste. */
const SP = String.raw`[ \t\u00a0]`;
/**
 * Between a label and its value: `SSN: `, `card number is `, `"cvv": "`, `PIN #`, a table cell, up to
 * two line breaks (a blank line in a form), and a bullet.
 */
const LABEL_GAP = String.raw`${SP}{0,3}(?:[_ -]?(?:number|num|no\.?|#)${SP}{0,3})?["']?${SP}{0,3}(?:(?:is|was)${SP}{0,3})?(?:[:=#|-]${SP}{0,3}|'s${SP}{1,3})?(?:(?:\\n|\r?\n)${SP}{0,3}){0,2}(?:[-*•]${SP}{1,3})?["'(*\`]{0,2}`;

/** A value right after one of the labels; the label and gap are group 1, the value group 2. */
function labeled(label: string, value: string): RegExp {
	return new RegExp(String.raw`((?:\b|(?<=_)|(?<=\\[nrt]))(?:${label})${LABEL_GAP})(${value})(?![\w-]|[.,]\d)`, "gi");
}

/** Example SSNs printed on cards, forms and docs, which the SSA never issued or retired. */
const EXAMPLE_SSNS = new Set(["123456789", "078051120", "219099999", "987654320"]);

/** Whether nine digits follow the SSA's issuing rules: no 000, 666 or 00 parts; 9xx only as an ITIN. */
function isIssuedSsn(d: string): boolean {
	if (/^(000|666)|^\d{3}00|0000$/.test(d) || EXAMPLE_SSNS.has(d) || /^(\d)\1+$/.test(d)) return false;
	return d[0] !== "9" || /^9\d\d(5\d|6[0-5]|7\d|8[0-8]|9[0-24-9])/.test(d);
}

function luhn(digits: string): boolean {
	let sum = 0;
	for (let i = 0; i < digits.length; i++) {
		let d = digits.charCodeAt(digits.length - 1 - i) - 48;
		if (i % 2) d = d * 2 > 9 ? d * 2 - 9 : d * 2;
		sum += d;
	}
	return sum % 10 === 0;
}

/** A card number by its network's prefix and length, and the Luhn check. */
function isCardNumber(d: string): boolean {
	const n = d.length;
	const fits =
		(/^4/.test(d) && (n === 16 || n === 19)) ||
		(/^(5[1-5]|222[1-9]|22[3-9]|2[3-6]|27[01]|2720)/.test(d) && n === 16) ||
		(/^3[47]/.test(d) && n === 15) ||
		(/^(6011|64[4-9]|65|62|35(2[89]|[3-8]))/.test(d) && n >= 16 && n <= 19) ||
		(/^3(0[0-5]|[689])/.test(d) && n >= 14 && n <= 19);
	return fits && luhn(d);
}

/** Published test cards (Stripe, Braintree, Adyen) that no pattern below already exempts. */
const TEST_CARDS = new Set([
	"378282246310005", "371449635398431", "378734493671000", "2223003122003222", "6011000990139424", "3566002020360505",
	"30569309025904", "38520000023237", "3056930009020004", "36227206271667", "5425233430109903", "2222420000001113",
	"4917484589897107", "4035501000000008", "4360000001000005", "6250941006528599", "4012000033330026", "4000056655665556",
	"4000002760003184", "4000003720000278",
]);

/** A test card: a published one, or a number made of repeats (`4242 4242…`, `4000 0000…`, `5105 1051…`). */
function isTestCard(d: string): boolean {
	return TEST_CARDS.has(d) || /(\d)\1{4}|(\d\d)\2{3}|(\d{3})\3{2}/.test(d);
}

/**
 * Card numbers: four groups of four, Amex's 4-6-5, Diners' 4-6-4, or the digits run together. Not as
 * a value under a JSON key or after `=` (`"value": 4…`, `id=4…`), or in a CSV cell, where it's an
 * identifier; the labeled rule catches `card_number=…` and `"cardNumber": …`.
 */
const CARD = new RegExp(String.raw`(?:(?<=\\[nrt])|(?<![\w\\.+/=:,#@<-]|\d[ -]|["']${SP}{0,3}:${SP}{0,3}["']?|=${SP}{0,3}["']?))(?:\d{4}([ -])\d{4}\1\d{4}\1\d{4}(?:\1\d{3})?|\d{4}([ -])\d{6}\2\d{4,5}|\d{13,19})(?![\w-]|[.,]\d|[ -]\d)`, "g");
/** A dashed SSN with no label, which must also follow the issuing rules. */
const SSN = /(?:(?<=\\[nrt])|(?<![\w\\.$/-]|\d ))(\d{3})-(\d{2})-(\d{4})(?![\w-]|[.,]\d)/g;
/** Words before a number that make it an identifier: `order 4…`, `span 4…`, `docket no. 512-…`. */
const ID_BEFORE = /\b(?:ids?|order|invoice|tracking|ref|reference|account|acct|ts|timestamp|seq|offset|nonce|hash|serial|span|parent|trace|txn|transaction|ticket|case|docket|part|model|sku|item|phone|tel|fax|no\.?|number|#)[ \t#:.]{0,3}$/i;

const SSN_LABEL = String.raw`SSNs?|SS${SP}?#|social${SP}security|social|ITIN|taxpayer${SP}identification|tax${SP}?id`;
const CARD_LABEL = String.raw`(?:credit|debit|bank|payment|visa|mastercard|amex)${SP}card|card|CC`;
const CVV_LABEL = String.raw`CVV2?|CVC2?|security${SP}code|sec${SP}code|card${SP}code|card${SP}verification(?:${SP}code|${SP}value)?`;
const CODE_LABEL = String.raw`PIN(?:${SP}code)?|passcode|pass${SP}code|door|lockbox|lock${SP}box|keypad|(?:door|gate|alarm|garage|keypad|key${SP}pad|entry|lockbox|lock${SP}box|lock|safe|unlock|disarm|voicemail|house|apartment|apt|elevator|mailbox)${SP}?(?:code|pin)`;
const PASSPORT_LABEL = String.raw`passport`;
const LICENSE_LABEL = String.raw`driver'?s?'?${SP}?licen[cs]e|driving${SP}licen[cs]e|DLN|DL(?=${SP}{0,2}(?:#|number|no\b|num))`;
/** PINs from manuals and defaults, which aren't anyone's. */
const DEFAULT_PINS = /^(0000|1234|12345|123456|(\d)\2+)$/;

/** Hides the personal data above, labeled or confirmed by a checksum. */
function redactPersonal(text: string): string {
	text = redactBackupCodes(redactTotpKeys(redactSeedPhrases(text)))
		// App passwords as Google and Apple print them: `abcd efgh ijkl mnop`, `abcd-efgh-ijkl-mnop`.
		.replace(new RegExp(String.raw`(\bpassword\b[^\n]{0,40}?[:\n]${SP}{0,3})([a-z]{4}(?:${SP}[a-z]{4}){3}|[a-z]{4}(?:-[a-z]{4}){3})(?![\w-])`, "gi"), (m, head, v) =>
			v === v.toLowerCase() ? `${head}[secret: app password]` : m,
		);
	if (!/\d{3}/.test(text)) return text;
	text = text.replace(/[\uff10-\uff19]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 0xfee0)).replace(/(?<=\d)[\u00a0\u2010-\u2015](?=\d)/g, (c) => (c === "\u00a0" ? " " : "-"));
	const digits = (v: string) => v.replace(/\D/g, "");
	return text
		.replace(labeled(SSN_LABEL, String.raw`\d{3}[- .]?\d{2}[- .]?\d{4}`), (m, head, v) =>
			EXAMPLE_SSNS.has(digits(v)) || /^(\d)\1+$/.test(digits(v)) ? m : `${head}[secret: SSN]`,
		)
		.replace(SSN, (m, a, b, c, offset: number, str: string) =>
			isIssuedSsn(a + b + c) && !ID_BEFORE.test(str.slice(Math.max(0, offset - 20), offset)) ? "[secret: SSN]" : m,
		)
		.replace(labeled(CARD_LABEL, String.raw`\d[\d -]{11,22}\d`), (m, head, v) => {
			const d = digits(v);
			return d.length >= 13 && d.length <= 19 && !isTestCard(d) ? `${head}[secret: card number]` : m;
		})
		.replace(CARD, (m, _a, _b, offset: number, str: string) => {
			const d = digits(m);
			return isCardNumber(d) && !isTestCard(d) && !ID_BEFORE.test(str.slice(Math.max(0, offset - 20), offset)) ? "[secret: card number]" : m;
		})
		.replace(labeled(CVV_LABEL, String.raw`\d{3,4}`), "$1[secret: card security code]")
		.replace(labeled(CODE_LABEL, String.raw`[*#]?\d{4,10}[#*]?`), (m, head, v) => (DEFAULT_PINS.test(digits(v)) ? m : `${head}[secret: code]`))
		.replace(labeled(PASSPORT_LABEL, String.raw`[A-Z0-9]{6,9}`), (m, head, v) => (/\d/.test(v) && v === v.toUpperCase() ? `${head}[secret: passport number]` : m))
		.replace(labeled(LICENSE_LABEL, String.raw`[A-Z0-9](?:[A-Z0-9]|[ -](?=[A-Z0-9])){5,19}`), (m, head, v) =>
			(v.match(/\d/g)?.length ?? 0) >= 4 && v === v.toUpperCase() ? `${head}[secret: license number]` : m,
		)
		// BitLocker recovery keys: eight groups of six digits, each a multiple of 11.
		.replace(/\b\d{6}(?:-\d{6}){7}\b/g, (m) => (m.split("-").every((g) => Number(g) % 11 === 0) ? "[secret: recovery key]" : m))
		// 1Password Secret Keys.
		.replace(/\bA3-[A-Z0-9]{6}-[A-Z0-9]{5,6}(?:-[A-Z0-9]{5}){4}\b/g, "[secret: recovery key]");
}

/** Base32 secrets printed in docs (Google Authenticator's wiki, RFC 6238), which aren't anyone's. */
const EXAMPLE_TOTP = /^(JBSWY3DPEHPK3PXP|GEZDGNBVGY3TQOJQ)/;

/**
 * Two-factor setup keys, the permanent seed behind every code an authenticator shows: base32, in
 * groups of four or run together, near the words that introduce one (`Can't scan? Enter this key`).
 * Hex-only groups are GPG fingerprints, not base32 keys.
 */
function redactTotpKeys(text: string): string {
	if (!/key|secret|2fa|factor|mfa|otp|authenticator|code/i.test(text)) return text;
	const re = new RegExp(String.raw`(?:(?<=\\[nrt])|(?<![\w\\/+=-]))(?:[A-Z2-7]{4}(?:([ -])[A-Z2-7]{4}(?:\1[A-Z2-7]{4}){2,14})|[a-z2-7]{4}(?:([ -])[a-z2-7]{4}(?:\2[a-z2-7]{4}){2,14})|[A-Z2-7]{16,64})(?![\w/+=-])`, "g");
	return text.replace(re, (m, _a, _b, offset: number, str: string) => {
		const key = m.replace(/[ -]/g, "");
		const grouped = key !== m;
		if ((key.match(/[2-7]/g)?.length ?? 0) < (grouped ? 1 : 2) || /^[A-F2-7]+$/i.test(key) || EXAMPLE_TOTP.test(key.toUpperCase())) return m;
		const before = str.slice(Math.max(0, offset - 80), offset);
		const trigger = grouped ? /\b(key|secret|code|2fa|two[- ]factor|mfa|totp|otp|authenticator)\b/i : /\b(key|secret|2fa|two[- ]factor|mfa|totp|otp|authenticator)\b/i;
		return trigger.test(before) ? "[secret: 2FA setup key]" : m;
	});
}

/** One backup code: `8f3k-2m9q`, `a1b2c-3d4e5`, `1234 5678`. */
const BACKUP_CODE = String.raw`(?:\d{4} \d{4}|(?=[A-Za-z0-9-]{0,60}\d)[A-Za-z0-9]{4,16}(?:-[A-Za-z0-9]{3,16}){0,7})`;
const BACKUP_CODE_RE = new RegExp(String.raw`(?<![\w#-])${BACKUP_CODE}(?![\w-])`, "g");
const BULLET = String.raw`(?:[-*•]|\d{1,2}[.)]|\[[ x]\])`;
const BACKUP_CODE_LINE = new RegExp(String.raw`^[ \t]{0,10}${BULLET}?[ \t]{0,5}${BACKUP_CODE}(?:[ \t,;|]{1,6}(?:${BULLET}[ \t]{1,4})?${BACKUP_CODE}){0,9}[ \t,;]{0,3}\r?$`);
const BACKUP_LABEL = /\b(?:backup|recovery|emergency|rescue|scratch|one[- ]time|single[- ]use)[ \t]codes?\b|\brecovery[ \t]keys?\b/i;
/** What follows a label that introduces codes: `:`, `are`, `(save these):`, or nothing, as in a heading. */
const BACKUP_INTRO = /^[ \t]{0,3}(?:\([^)\n]{0,60}\)[ \t]{0,3})?(?:(?:[:=]|\bare\b|\bis\b)(.*)|[ \t]*\r?$)/;

/**
 * Two-factor backup codes and recovery keys: after a label that introduces them, the codes on its line
 * and the lines of codes under it. Each one signs in once without the second factor.
 */
function redactBackupCodes(text: string): string {
	if (!BACKUP_LABEL.test(text)) return text;
	const mask = (s: string) =>
		s.replace(BACKUP_CODE_RE, (code) => (code.length >= 6 && !/^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(code) ? "[secret: backup code]" : code));
	// Lines and their separators, so `\n` escapes in a JSON chat export split lines too.
	const parts = text.split(/(\r?\n|\\n)/);
	for (let i = 0; i < parts.length; i += 2) {
		const label = parts[i].length < 2000 ? parts[i].match(BACKUP_LABEL) : null;
		if (!label) continue;
		const end = label.index! + label[0].length;
		const intro = parts[i].slice(end).match(BACKUP_INTRO);
		if (!intro) continue;
		if (intro[1]) parts[i] = parts[i].slice(0, end) + parts[i].slice(end).replace(intro[1], mask(intro[1]));
		for (let j = i + 2, blanks = 0; j < parts.length && j <= i + 80; j += 2) {
			if (!parts[j].trim()) {
				if (++blanks > 2) break;
				continue;
			}
			if (!BACKUP_CODE_LINE.test(parts[j])) break;
			parts[j] = mask(parts[j]);
			i = j;
		}
	}
	return parts.join("");
}

const BIP39_INDEX = new Map(BIP39_WORDS.map((w, i) => [w, i]));

/** Whether wordlist words are a BIP39 phrase: a valid length, and the last word's checksum bits match. */
function isSeedPhrase(words: string[]): boolean {
	if (![12, 15, 18, 21, 24].includes(words.length)) return false;
	const bits = words.map((w) => BIP39_INDEX.get(w)!.toString(2).padStart(11, "0")).join("");
	const entropyBits = (words.length * 32) / 3;
	const bytes = Buffer.alloc(entropyBits / 8);
	for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
	const check = createHash("sha256").update(bytes).digest()[0].toString(2).padStart(8, "0").slice(0, words.length / 3);
	return bits.slice(entropyBits) === check;
}

/** Words that introduce a phrase, and can lead its run since they're wordlist words too. */
const PHRASE_LEAD = /^(seed|phrase|secret|word|recovery|backup|wallet)$/;
const PHRASE_LABEL = /seed|mnemonic|recovery phrase|secret phrase|backup phrase|\b(12|24)[- ]words?\b/i;
/** Between the words of a phrase: spaces, line breaks, list numbering. Not quotes or commas, which make a list in code. */
const PHRASE_GAP = /^(?:[ \t]|\r?\n|\\n|\d{1,2}[.)](?!\d)|#\d{1,2}(?!\d)|\*\*\d{1,2}\.\*\*)+$/;

/**
 * Wallet recovery phrases: a run of exactly 12, 15, 18, 21 or 24 wordlist words, numbered or not,
 * that passes the checksum or follows a label like `seed phrase`. A run of any other length is a word
 * list, phrases with repeated words are test vectors, and so are lines that also hold hex or an xprv.
 */
function redactSeedPhrases(text: string): string {
	const spans: [number, number][] = [];
	let run: { word: string; start: number; end: number }[] = [];
	const close = () => {
		let lead = 0;
		while (lead < run.length && PHRASE_LEAD.test(run[lead].word)) lead++;
		const words = run.slice(lead).map((r) => r.word);
		if ([12, 15, 18, 21, 24].includes(words.length) && new Set(words).size >= words.length * 0.8) {
			const start = run[lead].start;
			const end = run.at(-1)!.end;
			const lineStart = text.lastIndexOf("\n", start) + 1;
			const lineEnd = text.indexOf("\n", end);
			const line = text.slice(lineStart, lineEnd < 0 ? undefined : lineEnd);
			const vector = line.length < 4000 && /[0-9a-f]{32}|xprv/i.test(line);
			if (!vector && (isSeedPhrase(words) || PHRASE_LABEL.test(text.slice(Math.max(0, start - 60), start)))) spans.push([start, end]);
		}
		run = [];
	};
	// `\n` escapes (a phrase in JSON) separate words; blanking them keeps every offset.
	for (const m of text.replace(/\\[nrt]/g, "  ").matchAll(/(?<![A-Za-z])[A-Za-z]{3,8}(?![A-Za-z])/g)) {
		const word = m[0].toLowerCase();
		const start = m.index!;
		if (run.length) {
			const gap = text.slice(run.at(-1)!.end, start);
			if (gap.length > 24 || !PHRASE_GAP.test(gap)) close();
		}
		if (BIP39_INDEX.has(word)) run.push({ word, start, end: start + m[0].length });
		else close();
	}
	close();
	if (!spans.length) return text;
	const out: string[] = [];
	let at = 0;
	for (const [start, end] of spans) {
		out.push(text.slice(at, start), "[secret: recovery phrase]");
		at = end;
	}
	return out.join("") + text.slice(at);
}

/** A value as it appears after a name: quoted, or unquoted up to a delimiter. */
const VALUE = String.raw`("(?:[^"\\\n]|\\.){1,500}"|'[^'\n]{1,500}'|[^\s"',;&)}\]|│]{1,500})`;
/** A name that could be a credential's; others never match, so they can't swallow the pairs inside their values. */
const NAME = String.raw`((?=[\w.-]{0,80}?(?:key|token|secret|pass|pwd|pw\b|psk|auth|cred|cookie|sig|salt|pin|pat\b|sid\b|sess))[A-Za-z_][\w.-]{0,80})`;

const NAMED_TRIGGER = /key|token|secret|pass|pwd|pw|psk|auth|cred|cookie|sig|salt|pin|pat|sid|sess|bearer|basic|:\/\/|define|value|@\/\/|\.\.\.|│|redis|-u |--user|mysql/i;

/** Kubernetes env entries: `- name: DB_PASSWORD`, then `value: <literal>` on the next line. */
function envValueLine(lines: string[], i: number, line = lines[i]): string | undefined {
	const envName = lines[i - 1]?.match(/^[ \t]{0,40}-[ \t]{1,5}name:[ \t]{0,5}["']?([\w.-]{1,80})["']?[ \t]{0,5}\r?$/)?.[1];
	if (!envName || !isCredentialName(envName)) return undefined;
	return line.replace(/^([ \t]{0,40}value:[ \t]{0,5})(\S.{0,500})$/, (m, a, value) => (isInert(cleanValue(value)) ? m : `${a}[secret]`));
}

/** A credential named in a sentence: `my netflix password is …`, `the wifi password's …`, `API key was: …`. */
const PROSE_PAIR = /\b([A-Za-z][\w-]{0,40}(?:[ \t][A-Za-z][\w-]{0,40})?)('s[ \t]{1,3}|[ \t]{1,3}(?:is|was)(?:[ \t]{1,3}(?:now|still|currently|actually|just))?[ \t]{0,3}:?[ \t]{1,3})(["'`]?)([^\s"'`]{1,300}?)\3(?=[.,;!?)\]]{0,3}(?:[\s"'`]|\\n|$))/g;
/** Words that follow `password is` in sentences about passwords rather than ones that give one. */
const PROSE_WORDS = new Set([
	"required", "incorrect", "invalid", "wrong", "correct", "missing", "empty", "blank", "set", "unset", "stored", "hashed",
	"encrypted", "saved", "changed", "reset", "expired", "too", "not", "the", "a", "an", "your", "my", "our", "their", "his",
	"her", "its", "this", "that", "same", "different", "still", "now", "also", "being", "been", "case", "case-sensitive",
	"sensitive", "mandatory", "weak", "strong", "long", "short", "okay", "fine", "good", "bad", "there", "here", "generated",
	"random", "provided", "given", "sent", "shown", "hidden", "visible", "used", "needed", "protected", "secure", "insecure",
	"valid", "unique", "only", "just", "always", "never", "usually", "probably", "somewhere", "written", "printed", "rotated",
	"revoked", "compromised", "leaked", "known", "unknown", "fake", "real", "temporary", "new", "old", "updated", "string",
	"str", "number", "int", "boolean", "bool", "text", "varchar", "bytes", "object", "any", "unknown", "nullable", "ignored",
	"correctly", "configured", "supported", "accepted", "rejected", "disabled", "enabled", "displayed", "masked", "redacted",
	"what", "which", "where", "when", "why", "how", "something", "anything", "nothing", "everything", "easy", "hard", "simple",
	"complex", "complicated", "different", "safe", "unsafe", "secret", "private", "public", "important", "useless", "gone",
	"bcrypt", "scrypt", "argon2", "argon2i", "argon2d", "argon2id", "pbkdf2", "md5", "sha1", "sha256", "sha512", "sha-1",
	"sha-256", "sha-512", "plaintext", "salted", "changeit", "optional", "configurable", "immutable", "readonly",
]);

/**
 * Whether a credential named in prose is followed by its value. Keys and tokens must look random;
 * a password can be any word, so one is taken when it ends the sentence or holds a digit, and isn't
 * a word that describes passwords (`password is incorrect`).
 */
function isProseSecret(name: string, raw: string, quoted: boolean, after: string): boolean {
	// The whole word as written, not a suffix: `the compass is …` names no credential.
	const last = words(name).at(-1) ?? "";
	// Markdown and HTML around a word (`**required**`, `<code>sub</code>`) aren't part of it.
	const value = raw.replace(/^(?:\*{1,2}|_{1,2}|<\w{1,10}>)|(?:\*{1,2}|_{1,2}|<\/\w{1,10}>)$/g, "");
	if (value.length < 4 || isInert(value) || isCode(value) || isPlaceholder(value) || /^[A-Z][A-Z0-9]*_[A-Z0-9_]+$/.test(value)) return false;
	if (/^(KEY|APIKEY|TOKEN|SECRET|CREDENTIALS?)$/.test(last)) return isCredentialName(name) && isRandomToken(value);
	if (!/^(PASSWORD|PASSWD|PASSCODE|PASSPHRASE|PWD|PW)$/.test(last)) return false;
	const lower = value.toLowerCase();
	if (COMMON_WORDS.has(lower) || PROSE_WORDS.has(lower) || DEFAULT_PINS.test(value) || /^\d{1,3}[-–]\d{1,3}$/.test(value)) return false;
	if (raw !== value || /^[a-z]+(-[a-z]+)+$/.test(value)) return false;
	if (looksSecret(value)) return true;
	return quoted || /\d/.test(value) || /^[.,;!?)\]]{0,3}[ \t]*(?:$|\r|\\n|(?:and|but|so|btw|if|or|lol|thanks|thx|please|pls|then|for|ok)\b)/i.test(after);
}

/**
 * Credential-named values in any output, in the syntaxes tools print them: `NAME=value` (env
 * listings, diffs, libpq strings, Java properties, terraform plans), `name: value` (YAML, JSON,
 * headers, dict reprs), tables (vault, doppler), command-line flags, connection strings, URL
 * passwords, Authorization headers, PHP `define()` and XML attributes. A value is masked only if it
 * also looks like a secret: not a type, label, path, placeholder or code. Works line by line.
 */
function redactNamedValues(text: string): string {
	const mask = (name: string, value: string, _strict = true) => isCredentialName(name.replace(/^[-+]+/, "")) && looksSecret(value);
	// "public key: …" names a public key: the word before a name counts as part of it.
	const maskAfter = (text: string, offset: number, name: string, value: string) => {
		const before = text.slice(Math.max(0, offset - 40), offset).match(/([A-Za-z]{2,30})[ \t]{1,3}["']?$/)?.[1];
		return mask(name, value) && (!before || isCredentialName(`${before}_${name}`));
	};
	const keepQuotes = (value: string) => (/^["']/.test(value) ? `${value[0]}[secret]${value[0]}` : "[secret]");
	const out: string[] = [];
	const lines = text.split("\n");
	for (let i = 0; i < lines.length; i++) {
		let line = lines[i];
		// Every rule below needs one of these words; most lines have none, so they skip the work.
		if (line.length > 20_000 || !NAMED_TRIGGER.test(line)) {
			out.push(envValueLine(lines, i) ?? line);
			continue;
		}
		// A whole-line `NAME=value` (env, export -p, declare -x) runs to the end of the line, spaces included.
		line = line.replace(/^([ \t]{0,10}(?:export[ \t]+|declare[ \t]+-x[ \t]+|set[ \t]+-gx[ \t]+)?)([A-Za-z_]\w{0,80})(=)(.{1,2000})$/, (m, a, name, eq, value) => {
			// Identifiers don't contain spaces, so a spaced value under a credential name is a passphrase.
			const v = cleanValue(value);
			const passphrase = / /.test(v) && v.length >= 8 && !isInert(v) && !isCode(value);
			return isCredentialName(name) && (looksSecret(value) || passphrase) ? `${a}${name}${eq}[secret]` : m;
		});
		// A quoted `"NAME=value"` entry (docker inspect, compose): the value runs to the closing quote.
		line = line.replace(/(["'])([A-Za-z_]\w{0,80})=((?:(?!\1)[^\\\n]|\\.){1,2000})\1/g, (m, q, name, value) => {
			const passphrase = / /.test(value) && value.length >= 8 && !isInert(value);
			return isCredentialName(name) && (looksSecret(value) || passphrase || (/[,;]/.test(value) && value.length >= 8)) ? `${q}${name}=[secret]${q}` : m;
		});
		line = line
			.replace(/(\bAuthorization["']?[ \t]{0,10}[:=][ \t]{0,10}["']?(?:Bearer|Basic|Token|Bot|Digest|ApiKey|SSWS|token|bearer|basic)[ \t]{1,10})([^\s"',;]{1,2000})/gi, "$1[secret]")
			.replace(/\b(Bearer|Basic)([ \t]{1,10})([A-Za-z0-9._~+/-]{16,2000}={0,2})/g, "$1$2[secret]")
			.replace(/\b([a-z][a-z0-9+.-]{0,20}:\/\/[^\s/?#@:]{0,200}:)([^\s]{1,300}?)(@[^\s@/?#"']{1,300}(?=[/?#:\s"']|$))/gi, (m, head, pw, tail) =>
				isUrlPassword(pw) ? `${head}[secret]${tail}` : m,
			)
			.replace(new RegExp(String.raw`(^|[^\w.])(["']?)${NAME}\2([ \t]{0,10}=[ \t]{0,10})${VALUE}`, "gi"), (m, before, q, name, eq, value, offset, str) =>
				maskAfter(str, offset + before.length, name, value) ? `${before}${q}${name}${q}${eq}${keepQuotes(value)}` : m,
			)
			.replace(new RegExp(String.raw`(^|[^\w.])(["']?)${NAME}\2([ \t]{0,10}:[ \t]{0,10})${VALUE}`, "gi"), (m, before, q, name, colon, value, offset, str) =>
				/^(set-)?cookie$/i.test(name) || /^\/\//.test(value) ? m : maskAfter(str, offset + before.length, name, value) ? `${before}${q}${name}${q}${colon}${keepQuotes(value)}` : m,
			)
			.replace(/(^|\s)(--?[A-Za-z][\w-]{0,60})([ \t]{1,10}|=)("[^"\n]{1,300}"|'[^'\n]{1,300}'|[^\s"'-][^\s"']{0,300})/g, (m, before, flag, eq, value) =>
				isCredentialName(flag.replace(/^-+/, "")) && looksSecret(value) ? `${before}${flag}${eq}${keepQuotes(value)}` : m,
			)
			.replace(/(\s(?:-u|--user)[ \t=]{1,5}[^\s:]{1,100}:)([^\s"']{1,300})/g, "$1[secret]")
			.replace(/(\b(?:mysql|mariadb)(?:dump|admin|-dump|-admin)?\b[^\n]{0,300}?\s-p)([^\s-][^\s]{0,200})/g, "$1[secret]")
			.replace(/\bdefine\([ \t]{0,10}(['"])([\w]{1,80})\1[ \t]{0,10},[ \t]{0,10}(['"])([^'"\n]{1,400})\3/g, (m, q, name, q2, value) =>
				mask(name, `${q2}${value}${q2}`, false) ? m.replace(`${q2}${value}${q2}`, `${q2}[secret]${q2}`) : m,
			)
			.replace(/\b(key|name)="([^"\n]{1,100})"([^>\n]{0,200}?\bvalue=")([^"\n]{1,500})"/gi, (m, _k, name, mid, value) =>
				mask(name, `"${value}"`, false) ? m.replace(`${mid}${value}"`, `${mid}[secret]"`) : m,
			)
			.replace(/"(?:name|label|key|keyName|Name|Key)"[ \t]{0,5}:[ \t]{0,5}"([^"\n]{1,100})"([^{}\n]{0,200}?"(?:value|Value)"[ \t]{0,5}:[ \t]{0,5}")((?:[^"\\\n]|\\.){1,2000})"/g, (m, name, mid, value) =>
				mask(name, `"${value}"`, false) || /^(Bearer|Basic) /.test(value) ? m.replace(`${mid}${value}"`, `${mid}[secret]"`) : m,
			);
		if (/;/.test(line)) {
			line = line.replace(/(^|[;"'\s])((?:User )?Password|Pwd|AccountKey|SharedAccessKey|SharedAccessSignature)=([^;"'\s]{1,500})/gi, "$1$2=[secret]");
		}
		line = line.replace(PROSE_PAIR, (m, name, link, q, value, offset: number, str: string) =>
			isProseSecret(name, value, q !== "", str.slice(offset + m.length)) ? `${name}${link}${q}[secret]${q}` : m,
		);
		// Tables: `password    hunter2`, `│ JWT_SECRET │ value │`.
		line = line.replace(/^([ \t│|]{0,10})([A-Za-z_][\w.-]{0,80})([ \t]{2,80}|[ \t]{0,80}[│|][ \t]{0,10})([^\s│|][^│|\n]{0,400}?)([ \t]{0,40}(?:[│|].{0,400})?\r?)$/, (m, a, name, sepr, value, end) =>
			mask(name, value) ? `${a}${name}${sepr}[secret]${end}` : m,
		);
		// Dot-leader rows (`artisan config:show`): `connections ⇁ mysql ⇁ password ...... value`.
		line = line.replace(/^(.{0,300}?)([A-Za-z_][\w-]{0,80})([ \t]\.{3,300}[ \t]{1,5})(\S.{0,400}?)([ \t]{0,20}\r?)$/, (m, a, name, sepr, value, end) =>
			mask(name, value) ? `${a}${name}${sepr}[secret]${end}` : m,
		);
		// nmcli --show-secrets: `802-11-wireless-security.psk:   value`, whose name starts with a digit.
		line = line.replace(/^([ \t]{0,10}(?:802-11-wireless-security|802-1x|wifi-sec|vpn\.secrets)\.(?:psk|password|wep-key\d|leap-password|private-key-password|[\w-]{0,40}password)[ \t]{0,10}:[ \t]{1,40})(\S.{0,400}?)([ \t]*\r?)$/, (m, a, v, end) =>
			isInert(cleanValue(v)) || v === "--" || /^<hidden>$/.test(v) ? m : `${a}[secret]${end}`,
		);
		// redis.conf and redis-cli: `requirepass value`, ACL `user name on >password`, CONFIG GET pairs.
		line = line
			.replace(/^([ \t]{0,10}(?:requirepass|masterauth|masteruser-password)[ \t]+)(\S.{0,400})$/i, (m, a, v) => (isInert(cleanValue(v)) ? m : `${a}[secret]`))
			.replace(/^([ \t]{0,10}user[ \t]+\S{1,100}[ \t].{0,200}?[ \t]>)(\S{1,400})/, "$1[secret]")
			.replace(/(\bredis-cli\b[^\n]{0,300}?\s-a[ \t]+)(\S{1,300})/, "$1[secret]");
		const prevPair = lines[i - 1]?.match(/^[ \t]{0,10}\d{1,5}\)[ \t]+"([\w.-]{1,80})"[ \t]*\r?$/);
		if (prevPair && isCredentialName(prevPair[1])) line = line.replace(/^([ \t]{0,10}\d{1,5}\)[ \t]+")([^"]{1,1000})(")/, (m, a, v, b) => (isInert(v) ? m : `${a}[secret]${b}`));
		// aws --output text: CREDENTIALS <key id> <expiry> <secret key> <session token>.
		line = line.replace(/^(CREDENTIALS\t[^\t]{1,200}\t[^\t]{1,200}\t)([^\t]{1,200})(\t)(.{1,4000})$/, "$1[secret]$3[secret]");
		// A random token as a URL's whole user part: Azure DevOps PATs.
		line = line.replace(/(:\/\/)([A-Za-z0-9_-]{20,200})(@)/g, (m, a, user, b) => (isRandomToken(user) || /^[a-z0-9]{52}$/.test(user) ? `${a}[secret]${b}` : m));
		// Oracle EZConnect: user/password@//host.
		line = line.replace(/\b([\w$#]{1,30}\/)([^\s@/]{4,100})(@\/\/)/g, (m, a, pw, b) => (looksSecret(pw) ? `${a}[secret]${b}` : m));
		line = envValueLine(lines, i, line) ?? line;
		// Cookies: mask the values, keep the attributes.
		line = line.replace(/^([ \t]{0,10}(?:< |> )?(?:set-)?cookie:[ \t]{0,10})(.{1,4000})$/i, (_m, head, cookies) =>
			head +
			cookies.replace(/(^|;[ \t]{0,5})([^=;\s]{1,100})=([^;]{0,2000})/g, (m: string, sepr: string, name: string) =>
				/^(domain|path|expires|max-age|samesite|secure|httponly|priority|partitioned)$/i.test(name) ? m : `${sepr}${name}=[secret]`,
			),
		);
		out.push(line);
	}
	return out.join("\n");
}

/**
 * Masks every value under data:/stringData: of a Kubernetes Secret, whatever it's called. Works per
 * YAML document, so a ConfigMap next to a Secret keeps its data, and at any indent (kubectl Lists).
 */
function maskKubeSecretData(text: string): string {
	return text
		.split(/(?<=\n)(?=---[ \t]*\r?\n)/)
		.map((doc) => {
			if (!/^[ \t-]*kind:[ \t]*Secret\b/m.test(doc)) return doc;
			let dataIndent = -1;
			return doc
				.split("\n")
				.map((line) => {
					const indent = line.match(/^[ \t-]*/)![0].length;
					if (dataIndent >= 0 && line.trim() && indent <= dataIndent) dataIndent = -1;
					if (/^[ \t-]*(data|stringData):[ \t]*\r?$/.test(line)) {
						dataIndent = indent;
						return line;
					}
					if (dataIndent < 0) return line;
					return line.replace(/^([ \t]+[\w.-]+:[ \t]*)(\S.*)$/, (m, head, value) => (isInert(cleanValue(value)) || /^\[secret/.test(value) ? m : `${head}[secret]`));
				})
				.join("\n");
		})
		.join("");
}

/**
 * For output that is one JSON document (aws, az, gcloud, kubectl, op with -o json), credential values
 * found by walking it, including `{"name": "password", "value": …}` pairs split across lines.
 */
function redactJsonDocument(text: string): string {
	if (text.length > 5_000_000 || !/^[ \t]*[{[]/m.test(text)) return text;
	// One document, or several printed one after another (`aws …; terraform output -json`).
	const docs: unknown[] = [];
	for (const chunk of text.split(/\n(?=[{[])/)) {
		if (!/^\s*[{[]/.test(chunk)) continue;
		try {
			docs.push(JSON.parse(chunk));
		} catch {}
	}
	for (const [name, raw] of docs.flatMap((doc) => [...jsonPairs(doc)])) {
		const value = JSON.parse(raw) as string;
		if ((isCredentialName(name) || name === "secret") && looksSecret(raw)) {
			const escaped = JSON.stringify(value).slice(1, -1);
			text = text.split(`"${escaped}"`).join(`"[secret]"`);
		}
	}
	return text;
}

// --- Encodings ---------------------------------------------------------------------------------

/** The forms a known value takes in output, besides itself. Long multi-line values (keys) keep only their lines. */
function variants(value: string): string[] {
	if (value.length > 200 || value.includes("\n")) {
		const out = new Set([value, JSON.stringify(value).slice(1, -1)]);
		for (const line of value.split("\n")) if (line.trim().length >= 16) out.add(line.trim());
		return [...out];
	}
	const out = new Set([value]);
	const json = JSON.stringify(value).slice(1, -1);
	out.add(json);
	out.add(json.replace(/\//g, "\\/"));
	out.add(json.replace(/[&<>]/g, (c) => `\\u00${c.charCodeAt(0).toString(16)}`));
	let uri = value;
	try {
		uri = encodeURIComponent(value);
	} catch {} // lone surrogates
	out.add(uri);
	out.add(uri.replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`).replace(/%20/g, "+"));
	out.add(value.replace(/([^\w\-.,:/@+=%])/g, "\\$1")); // printf %q, backslash-escaped
	out.add(value.replace(/(["\\$`])/g, "\\$1")); // inside double quotes (declare -p, export -p)
	out.add(value.replace(/'/g, "'\\''")); // inside single quotes (set, set -x)
	out.add(value.replace(/\$/g, "$$$$")); // docker compose config
	const hex = Buffer.from(value).toString("hex");
	out.add(hex);
	out.add(hex.toUpperCase());
	if (/^[0-9a-f]+$/i.test(value)) {
		out.add(value.toLowerCase());
		out.add(value.toUpperCase());
	}
	return [...out].filter((v) => v.length >= 6);
}

/** Decoded text, or undefined for binary data. Tries UTF-8, then UTF-16LE (PowerShell). */
function decodeText(bytes: Buffer): string | undefined {
	if (bytes.length < 4) return undefined;
	const controls = (s: string) => s.replace(/[^\x00-\x08\x0b\x0c\x0e-\x1f\ufffd]/g, "").length;
	const utf8 = bytes.toString("utf8");
	if (controls(utf8) <= utf8.length * 0.1) return utf8;
	// UTF-16LE text (PowerShell) is mostly ASCII, so most high bytes are zero; anything else is binary.
	let zeros = 0;
	for (let i = 1; i < bytes.length; i += 2) if (bytes[i] === 0) zeros++;
	if (zeros < (bytes.length / 2) * 0.7) return undefined;
	const utf16 = bytes.toString("utf16le");
	return controls(utf16) <= utf16.length * 0.1 ? utf16 : undefined;
}

function decodeBase64(blob: string): string | undefined {
	const compact = blob.replace(/\\r|\\n|\s+/g, "");
	if (compact.length < 8) return undefined;
	return decodeText(Buffer.from(compact, "base64"));
}

/** Finds known values in text in linear time: a rolling hash over each value's first 16 characters. */
class LiteralIndex {
	private static readonly W = 16;
	private buckets = new Map<number, string[]>();
	size = 0;
	/** Characters a value is made of, used to find the whole of a value that output cut short. */
	static readonly TOKEN = /[A-Za-z0-9+/=_-]/;

	add(value: string) {
		const h = LiteralIndex.hash(value, 0);
		const bucket = this.buckets.get(h);
		if (bucket) {
			if (!bucket.includes(value)) bucket.push(value);
		} else this.buckets.set(h, [value]);
		this.size++;
	}

	sort() {
		for (const bucket of this.buckets.values()) bucket.sort((a, b) => b.length - a.length);
	}

	private static hash(s: string, start: number): number {
		let h = 0;
		for (let i = start; i < start + LiteralIndex.W; i++) h = (Math.imul(h, 31) + s.charCodeAt(i)) | 0;
		return h;
	}

	/**
	 * Each run of value characters that starts or ends with one of these 16-character markers, as
	 * [start, end]. Output that cut a value short (`head -c`, a truncated log) keeps one of its ends,
	 * so the surrounding run is replaced whole rather than left as a usable fragment.
	 */
	findRuns(text: string): [number, number][] {
		const runs: [number, number][] = [];
		for (const [at] of this.find(text)) {
			let start = at;
			let end = at + LiteralIndex.W;
			while (start > 0 && LiteralIndex.TOKEN.test(text[start - 1])) start--;
			while (end < text.length && LiteralIndex.TOKEN.test(text[end])) end++;
			if (runs.length && runs[runs.length - 1][1] >= start) runs[runs.length - 1][1] = Math.max(runs[runs.length - 1][1], end);
			else runs.push([start, end]);
		}
		return runs;
	}

	/** Each match as [start, value], leftmost-longest, without overlaps. */
	find(text: string): [number, string][] {
		const W = LiteralIndex.W;
		const found: [number, string][] = [];
		if (text.length < W || !this.buckets.size) return found;
		let pow = 1;
		for (let i = 0; i < W - 1; i++) pow = Math.imul(pow, 31);
		let h = LiteralIndex.hash(text, 0);
		for (let i = 0; i + W <= text.length; ) {
			const bucket = this.buckets.get(h);
			const hit = bucket?.find((v) => text.startsWith(v, i));
			if (hit) {
				found.push([i, hit]);
				const next = i + hit.length;
				if (next + W > text.length) break;
				h = LiteralIndex.hash(text, next);
				i = next;
				continue;
			}
			if (i + W >= text.length) break;
			h = (Math.imul(h - Math.imul(text.charCodeAt(i), pow), 31) + text.charCodeAt(i + W)) | 0;
			i++;
		}
		return found;
	}
}

// --- Which files are secret ------------------------------------------------------------------

const EXAMPLE = /\.(example|sample|template|defaults?|dist)$|^(example|sample|template)[._-]|\.(example|sample|template)\./i;
const SECRET_NAMES = [
	/^\.env([.-].+)?$/,
	/^[^.].*\.env$/,
	/^\.envrc$/,
	/^\.dev\.vars$/,
	/^\.secrets?$/,
	/^id_(rsa|dsa|ecdsa|ed25519)(_sk)?$/,
	/\.(key|p12|pfx|jks|keystore|ppk|keytab)$/i,
	/^credentials(\.(json|ya?ml|toml|ini|csv))?$/,
	/^\.(git-credentials|netrc|npmrc|pypirc|vault-token|pgpass|my\.cnf|s3cfg|boto|dockercfg|htpasswd|terraformrc)$/,
	/^(_netrc|rclone\.conf|cookies\.txt|keystore\.properties|wp-config\.php|\.?htpasswd|redis\.conf|sentinel\.conf|mongo(db)?[-_.]?keyfile|keyfile)$/i,
	/\.decrypt\.private\.php$/,
	/(^|[-_.])secrets?(\.[\w-]{1,40})?\.(json|ya?ml|toml|env|ini|properties)$/i,
	/\.(tfvars|tfstate)(\.json|\.backup)?$/,
	/^kubeconfig(\..+)?$|\.kubeconfig$/,
	/^(service[-_]?account|client[-_]secret|application_default_credentials).*\.json$/i,
];
/** Files inside a `secrets` directory (Docker, Kubernetes, CI), unless they're code. */
const IN_SECRETS_DIR = /(^|\/)\.?secrets\/(?:[^/]+\/)*[^/]+$/;
const CODE_FILE = /\.(ts|tsx|js|jsx|mjs|cjs|py|rb|go|rs|java|kt|cs|php|swift|c|h|cpp|md|html|css|sh)$/i;
/** `.pem`, `.crt`: secret only when they hold a private key, decided by content. */
const MAYBE_KEY = /\.(pem|crt|cer)$/i;
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
/** Commands that print file contents, so naming a secret file prints its secrets. */
const CONTENT_COMMANDS = /^(cat|tac|head|tail|less|more|bat|batcat|nl|sed|awk|gawk|grep|egrep|fgrep|rg|ag|cut|sort|uniq|strings|xxd|od|hexdump|base64|tr|column|jq|yq|type|Get-Content|gc|diff|comm)$/;
/** Commands whose whole output is a credential. */
const SECRET_COMMANDS = [
	/\bgh\s+auth\s+token\b/,
	/\bop\s+read\b|\bop\s+item\s+get\b.*--(fields|reveal)\b/,
	/\bdoppler\s+secrets\s+get\b.*--plain\b/,
	/\bheroku\s+auth:token\b/,
	/\bgcloud\s+auth\s+(application-default\s+)?print-(access|identity)-token\b/,
	/\bgcloud\s+secrets\s+versions\s+access\b/,
	/\baws\s+ecr(-public)?\s+get-login-password\b/,
	/\baz\s+account\s+get-access-token\b.*(-o|--output)\s+tsv\b/,
	/\bvault\s+(kv\s+get|read)\b.*-field\b/,
	/\bsecurity\s+find-(generic|internet)-password\b.*\s-w\b/,
	/\bopenssl\s+rand\b/,
	/\bpass\s+(show\s+)?[\w/.-]+\s*$/,
	/\bbw\s+get\s+(password|totp)\b/,
	/\bnpm\s+token\s+create\b/,
	/\bfirebase\s+login:ci\b/,
	/\bkubectl\b.*jsonpath.*\|\s*base64\s+(-d|--decode)\b/,
];

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

// --- Masking -------------------------------------------------------------------------------------

const KV_LINE = /^([ \t]{0,40}(?:#[ \t]{0,5})?(?:export[ \t]+|declare[ \t]+-x[ \t]+|set[ \t]+|-[ \t]+)?["']?)([\w.\-/@]{1,200})(["']?[ \t]{0,20}(?:=|:(?!\/\/)|[ \t](?=[ \t]*["']))[ \t]{0,20})(.{0,4000}?)(\r?)$/;

/**
 * Masks one value in a secret file, keeping its quotes and any trailing comment so the agent can still
 * see the file's shape and write a valid edit. Credential names hide the value; other names only hide
 * what is unmistakably a credential.
 */
function maskValue(name: string, raw: string): string {
	const quoted = raw.match(/^([ \t]*["'`])((?:[^"'`\\]|\\.)*)(["'`][ \t]*(?:#.*)?[ \t]*)$/);
	const commented = quoted ? undefined : raw.match(/^([ \t]*)(.*?)([ \t]+#.*[ \t]*)$/);
	const open = quoted?.[1] ?? commented?.[1] ?? "";
	const body = quoted?.[2] ?? commented?.[2] ?? raw.trim();
	const close = quoted?.[3] ?? commented?.[3] ?? "";
	const masked = maskBody(name, body);
	if (masked === body) return raw;
	return quoted || commented ? `${open}${masked}${close}` : raw.replace(body, masked);
}

/** The replacement for a value's text, or the text itself when it stays. */
function maskBody(name: string, body: string): string {
	const value = cleanValue(body);
	if (isInert(value) || /^[|>][-+]?$|^[{[]$/.test(value) || SSH_PUBLIC_KEY.test(value)) return body;
	if (isCredentialName(name) || (isCredentialWhenRandom(name) && hasRandomToken(value))) return "[secret]";
	// A name that says the value identifies something (CLIENT_ID, *_URL, DYNAMO sort key) shows it,
	// unless it holds a recognizable credential or a URL password.
	if (words(name).some((w) => IDENTIFIER_WORDS.has(w)) || PUBLIC_PREFIX.test(name)) {
		return redactUnmistakable(redactFormats(body, () => "[secret]"));
	}
	if (/^[0-9a-f]{32,}$/i.test(value) && !/(ID|SHA|HASH|COMMIT|REV|REVISION|FINGERPRINT|DIGEST|CHECKSUM|ETAG|VERSION)$/.test(words(name).at(-1) ?? "")) return "[secret]";
	return maskInline(body);
}

/** Hides credentials inside text that isn't a credential itself: URL passwords, tokens, random strings. */
function maskInline(text: string): string {
	text = redactPrivateKeys(text, "[private key withheld]");
	text = redactFormats(text, () => "[secret]");
	text = redactNamedValues(text);
	if (/public[ _-]?key|pubkey/i.test(text) || SSH_PUBLIC_KEY.test(text)) return text;
	// Path segments of URLs aren't keys.
	return text.replace(/[A-Za-z0-9+/=_-]{16,4096}/g, (token, at: number) =>
		text[at - 1] === "/" && /:\/\//.test(text.slice(0, at)) ? token : isRandomToken(token) ? "[secret]" : token,
	);
}

function maskLine(line: string, fileName: string): string {
	if (fileName === ".pgpass") return line.replace(/^((?:[^:\\\n]|\\.){0,300}:(?:[^:\\\n]|\\.){0,300}:(?:[^:\\\n]|\\.){0,300}:(?:[^:\\\n]|\\.){0,300}:)(.+)$/, "$1[secret]");
	if (/netrc$/.test(fileName)) return line.replace(/\b(password|account)([ \t]+)(\S+)/g, "$1$2[secret]");
	if (fileName === "cookies.txt" && /^[^#\s]/.test(line)) return line.replace(/\t([^\t]*)$/, (m, v) => (isRandomToken(v) || looksSecret(v) ? "\t[secret]" : m));
	if (/htpasswd$/i.test(fileName)) return line.replace(/^([^:#\s]{1,100}:)(.+)$/, "$1[secret]");
	if (/\.decrypt\.private\.php$/.test(fileName)) return line.replace(/"(?:[^"\\\n]|\\.){8,4000}"|'[^'\n]{8,4000}'/g, '"[secret]"');
	// JSON pairs anywhere on the line, so minified files work too.
	if (/^[ \t]*[{["]/.test(line) || /"[ \t]*:[ \t]*/.test(line)) {
		return line.replace(/("([^"\\\n]{1,200})"[ \t]{0,10}:[ \t]{0,10})("(?:[^"\\\n]|\\.){0,4000}"|[^,}\]\s]{1,500})/g, (_m, head, name, value) =>
			`${head}${maskValue(name, value) === value ? value : `"[secret]"`}`,
		);
	}
	// `requirepass secret`, `masterauth secret`: config formats that separate name and value with spaces.
	const spaced = line.match(/^([ \t]{0,20})([a-z][\w.-]{1,60})([ \t]+)([^=:\s].{0,2000})$/);
	if (spaced && isCredentialName(spaced[2]) && !isInert(cleanValue(spaced[4]))) return `${spaced[1]}${spaced[2]}${spaced[3]}[secret]`;
	// A Redis ACL rule: `user worker on >password ~jobs:* +@all`.
	if (/^[ \t]{0,20}user[ \t]/.test(line)) return line.replace(/([ \t]>)(\S{1,400})/g, "$1[secret]");
	const xml = line.replace(/<([\w:.-]{1,100})>([^<\n]{0,2000})<\/\1>/g, (m, name, value) => (isCredentialName(name) && !isInert(value.trim()) ? `<${name}>[secret]</${name}>` : m));
	if (xml !== line) return xml;
	const kv = line.match(KV_LINE);
	if (kv) {
		const masked = maskValue(kv[2], kv[4]);
		return masked === kv[4] ? line : `${kv[1]}${kv[2]}${kv[3]}${masked}${kv[5]}`;
	}
	// A lone token on a line of a secret file is a value: a bare token file, or `cut -d= -f2` output.
	const bare = line.trim();
	const isName = /^[A-Za-z_][A-Za-z0-9_]*$/.test(bare) && bare === bare.toUpperCase();
	// Structure that `diff` prints around the lines it shows.
	if (/^(\d+(,\d+)?[acd]\d+(,\d+)?|@@ .{0,200}|[-+]{3} .{0,300}|[<>]|\d+(,\d+)?[acd])$/.test(bare)) return line;
	if (/^[A-Za-z0-9+/=_.~!@#$%^&*-]{4,}$/.test(bare) && !isName && !/^\.?\p{L}+([_.-]\p{L}+)*$/u.test(bare) && !isInert(bare) && !/^age1[0-9a-z]{58}$/.test(bare)) {
		return line.replace(bare, "[secret]");
	}
	return maskInline(line);
}

// --- The registry ----------------------------------------------------------------------------

interface FileEntry {
	mtimeMs: number;
	size: number;
	values: [string, string][];
}

export class Secrets {
	private config: SecretsConfig;
	private extra: RegExp[];
	private exempt: RegExp[];
	private home = homedir();
	private files = new Map<string, FileEntry>();
	private walkedAt = 0;
	private walkedCwd = "";
	/** Known values: long ones through the rolling-hash index, short ones only as whole words. */
	private long = new LiteralIndex();
	/** The first and last 16 characters of every long value, to catch a value output cut short. */
	private ends = new LiteralIndex();
	private endLabels = new Map<string, string>();
	private short: RegExp[] = [];
	private labels = new Map<string, string>();
	/** Bumped whenever the set of values changes, so cached redactions can be reused until then. */
	version = 0;

	constructor(config: SecretsConfig) {
		this.config = config;
		this.extra = config.paths.map(globToRegex);
		this.exempt = config.notSecret.map(globToRegex);
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
		const name = basename(path);
		return (
			this.extra.some((r) => r.test(path)) ||
			SECRET_NAMES.some((r) => r.test(name)) ||
			MAYBE_KEY.test(name) ||
			IN_SECRETS_DIR.test(path) ||
			name === "auth.json" ||
			name === "mcp-auth.json" ||
			path.startsWith("~/") ||
			path.startsWith(this.home)
		);
	}

	private matches(path: string): boolean {
		if (this.exempt.some((r) => r.test(path))) return false;
		if (this.extra.some((r) => r.test(path))) return true;
		const name = basename(path);
		if (EXAMPLE.test(name) || name.endsWith(".pub")) return false;
		if (SECRET_NAMES.some((r) => r.test(name))) return true;
		if (IN_SECRETS_DIR.test(path) && !CODE_FILE.test(name)) return true;
		if (MAYBE_KEY.test(name)) return holdsPrivateKey(path);
		if (path === join(this.config.agentDir, "auth.json") || path === join(this.config.agentDir, "mcp-auth.json")) return true;
		const rel = relative(this.home, path).split(sep).join("/");
		if (rel.startsWith("..") || isAbsolute(rel)) return false;
		return HOME_SECRETS.some((s) => (s.endsWith("/") ? rel.startsWith(s) : rel === s)) && !NOT_SECRET_IN_HOME.test(rel);
	}

	private expand(token: string, cwd: string): string {
		const home = token.replace(/^(~|\$HOME|\$\{HOME\})(?=\/|$)/, this.home);
		return resolve(cwd, home);
	}

	/**
	 * Secret files whose contents a shell command prints: arguments of `cat`, `grep`, `sed` and other
	 * content commands. Only the segment of a pipeline that names the file counts.
	 */
	printedSecretFiles(command: string, cwd: string): string[] {
		const found: string[] = [];
		const segments = command.split(/\|\||&&|[|;\n]/);
		// Every part of the command has to be one that prints file contents, or the output holds other
		// things too (`cat .env && npm test`) and masking it all as file content would hide them.
		for (const segment of segments) {
			const tokens = segment.trim().split(/[\s<>`'"=()]+/).filter(Boolean);
			const program = basename(tokens.find((t) => !/^\w+=/.test(t) && t !== "sudo" && t !== "env") ?? "");
			if (!program || program === "cd") continue;
			const gitShow = program === "git" && tokens.some((t) => t === "show" || t === "cat-file");
			if (!CONTENT_COMMANDS.test(program) && !gitShow) return [];
		}
		for (const segment of segments) {
			const tokens = segment.trim().split(/[\s<>`'"=()]+/).filter(Boolean);
			const program = basename(tokens.find((t) => !/^\w+=/.test(t) && t !== "sudo" && t !== "env") ?? "");
			// `cd ../other && cat .env` resolves the file against the directory it changed to.
			if (program === "cd" && tokens[1]) {
				cwd = this.expand(tokens[1], cwd);
				continue;
			}
			const gitShow = program === "git" && tokens.some((t) => t === "show" || t === "cat-file");
			if (!CONTENT_COMMANDS.test(program) && !gitShow) continue;
			for (let token of tokens) {
				if (token.startsWith("-") || token.length > 300) continue;
				// `git show HEAD:.env` prints the file as committed.
				if (gitShow && token.includes(":")) token = token.slice(token.indexOf(":") + 1);
				const path = this.expand(token, cwd);
				if (/[*?]/.test(basename(path))) {
					// A glob the shell will expand, like `.env*`.
					const pattern = globToRegex(basename(path));
					try {
						for (const name of readdirSync(dirname(path))) {
							const candidate = join(dirname(path), name);
							if (pattern.test(name) && this.isSecret(candidate) && isFile(candidate)) found.push(candidate);
						}
					} catch {}
				} else if ((gitShow || (this.mightBeSecret(path) && isFile(path))) && this.isSecret(path)) found.push(path);
			}
		}
		return found;
	}

	/**
	 * Whether a command's whole output is a credential, like `gh auth token` or `op read`. Only the last
	 * command of a pipeline writes the output, and `$(op read …)` inside an argument doesn't.
	 */
	printsSecret(command: string): boolean {
		const plain = command.replace(/\$\([^()]{0,2000}\)|`[^`]{0,2000}`/g, "");
		if (/jsonpath.{0,500}\|\s*base64\s+(-d|--decode)\s*$/.test(plain)) return true;
		const last = plain.split(/\|\|?|&&|;/).at(-1) ?? "";
		return SECRET_COMMANDS.some((r) => r.test(last));
	}

	/** A secret file's contents with credential values hidden and everything else kept. */
	mask(text: string, fileName = ""): string {
		text = maskKubeSecretData(redactPrivateKeys(text, "[private key withheld]"));
		const lines = text.split("\n").filter((l) => l.trim());
		const catA = lines.length > 1 && lines.filter((l) => /(\^M)?\$$/.test(l)).length >= lines.length * 0.8;
		let blockIndent = -1;
		return text
			.split("\n")
			.map((line) => {
				// `cat -n` and `nl` put a line number and a tab first.
				const numbered = line.match(/^[ \t]{0,10}\d{1,9}\t/)?.[0] ?? "";
				const marker = catA ? (line.match(/(\^M)?\$$/)?.[0] ?? "") : "";
				const body = line.slice(numbered.length, line.length - marker.length);
				const indent = body.match(/^[ \t]*/)![0].length;
				// The lines of a YAML block scalar under a credential name: `password: |`.
				if (blockIndent >= 0) {
					if (body.trim() === "" || indent > blockIndent) return body.trim() ? `${numbered}${body.slice(0, indent)}[secret]${marker}` : line;
					blockIndent = -1;
				}
				const block = body.match(/^[ \t]*-?[ \t]*["']?([\w.-]{1,100})["']?[ \t]*:[ \t]*[|>][-+]?[ \t]*\r?$/);
				if (block && isCredentialName(block[1])) blockIndent = indent;
				return /\[secret\]/.test(body) ? line : numbered + maskLine(body, fileName) + marker;
			})
			.join("\n");
	}

	/**
	 * Masks lines of grep-style output that come from secret files: `path:12: text`, `path-12- text`,
	 * `path:text`, `rev:path:12:text` from git grep, and rg --heading groups. Paths may contain : and -.
	 */
	maskAttributedLines(text: string, cwd: string): string {
		const checked = new Map<string, boolean>();
		const fromSecretFile = (path: string) => {
			if (!path || path.length > 400 || !/[./]/.test(path)) return false;
			let result = checked.get(path);
			if (result === undefined) {
				const abs = this.expand(path, cwd);
				result = this.mightBeSecret(abs) && this.isSecret(abs) && isFile(abs);
				checked.set(path, result);
			}
			return result;
		};
		let heading: string | undefined;
		return text
			.split("\n")
			.map((line) => {
				if (line.length > 20_000) return line;
				// rg --heading: a path on its own line, then `12:text` lines until a blank line.
				if (line.trim() === "") heading = undefined;
				else if (!/^\d+[:-]/.test(line) && fromSecretFile(line.trim())) {
					heading = line.trim();
					return line;
				} else if (heading && /^\d+[:-]/.test(line)) {
					const at = line.match(/^\d+[:-]/)![0].length;
					return line.slice(0, at) + maskLine(line.slice(at), basename(heading));
				} else if (!/^\d+[:-]/.test(line)) heading = undefined;
				const separators = [...line.slice(0, 1000).matchAll(/:\d+[:-] ?|-\d+- ?|:/g)].slice(0, 8);
				for (const s of separators) {
					const before = line.slice(0, s.index);
					const starts = [0, ...[...before.matchAll(/:/g)].map((m) => m.index! + 1)].slice(0, 4);
					for (const start of starts) {
						if (!fromSecretFile(before.slice(start))) continue;
						const at = s.index! + s[0].length;
						return line.slice(0, at) + maskLine(line.slice(at), basename(before.slice(start)));
					}
				}
				return line;
			})
			.join("\n");
	}

	/** Replaces known values, encoded known values, and credentials recognizable by pattern. */
	redact(text: string): string {
		const broad = this.config.patterns === "broad";
		text = redactPrivateKeys(text, "[secret: private key]");
		if (broad) text = redactJsonDocument(text);
		if (/kind:[ \t]*Secret\b/.test(text)) text = maskKubeSecretData(text);
		text = this.redactBlobs(text);
		text = this.replaceKnown(text);
		text = redactFormats(text, (name) => `[secret: ${name}]`);
		text = redactPersonal(redactSignInLinks(text));
		return broad ? redactNamedValues(text) : redactUnmistakable(text);
	}

	private replaceKnown(text: string): string {
		const hits = this.long.find(text);
		if (hits.length) {
			let out = "";
			let at = 0;
			for (const [start, value] of hits) {
				out += `${text.slice(at, start)}[secret: ${this.labels.get(value) ?? "value"}]`;
				at = start + value.length;
			}
			text = out + text.slice(at);
		}
		for (const re of this.short) text = text.replace(re, (m) => `[secret: ${this.labels.get(m) ?? "value"}]`);
		// Whatever is left of a value that the output cut short.
		const runs = this.ends.findRuns(text);
		if (runs.length) {
			let out = "";
			let at = 0;
			for (const [start, end] of runs) {
				const run = text.slice(start, end);
				const label = this.endLabels.get(run.slice(0, 16)) ?? this.endLabels.get(run.slice(-16)) ?? "value";
				out += `${text.slice(at, start)}[secret: part of ${label}]`;
				at = end;
			}
			text = out + text.slice(at);
		}
		return text;
	}

	/** Whether decoded text holds a known value or a recognizable credential. */
	private holdsSecret(decoded: string): string | undefined {
		const long = this.long.find(decoded)[0];
		if (long) return this.labels.get(long[1]) ?? "a secret";
		for (const re of this.short) {
			re.lastIndex = 0;
			const hit = re.exec(decoded);
			re.lastIndex = 0;
			if (hit) return this.labels.get(hit[0]) ?? "a secret";
		}
		if (PRIVATE_KEY_BEGIN.test(decoded)) return "a private key";
		for (const [label, pattern] of TOKEN_FORMATS) {
			pattern.lastIndex = 0;
			const hit = pattern.test(decoded);
			pattern.lastIndex = 0;
			if (hit) return `a ${label}`;
		}
		if (redactNamedValues(decoded) !== decoded) return "a credential";
		return undefined;
	}

	/**
	 * Replaces base64 and hex blobs that decode to a secret: `base64 .env`, a cluster Secret, a Basic
	 * auth header, base64 inside JSON with `\n` escapes, `xxd -p`, and xxd, od or hexdump dumps.
	 * Wrapped lines are joined before decoding.
	 */
	private redactBlobs(text: string): string {
		// Dumps with offsets: xxd, hexdump -C, od -A x -t x1, and plain hexdump (16-bit words, byte-swapped).
		text = text.replace(/(?:^[0-9a-f]{6,8}:?(?:[ \t]{1,4}[0-9a-f]{2,4}){1,16}[^\n]{0,80}(?:\n|$)){1,100000}/gim, (dump) => {
			const words16: string[] = [];
			const bytes = dump
				.split("\n")
				.map((line) => {
					const body = line.replace(/^[0-9a-f]{6,8}:?[ \t]+/i, "");
					const hexPart = /\|.*\|[ \t]*$/.test(body) ? body.replace(/\|.*\|[ \t]*$/, "") : body.split(/[ \t]{2,}(?=[^0-9a-f \t]|[0-9a-f]{5,})/i)[0];
					for (const w of hexPart.match(/\b[0-9a-f]{4}\b/gi) ?? []) words16.push(w.slice(2) + w.slice(0, 2));
					return hexPart;
				})
				.join("")
				.replace(/[^0-9a-f]/gi, "");
			const decodings = [bytes, words16.join("")].filter((h) => h.length >= 12 && h.length % 2 === 0);
			for (const hex of decodings) {
				const decoded = Buffer.from(hex, "hex").toString("utf8");
				const found = this.holdsSecret(decoded);
				if (found) return `[secret: hex dump of ${found}]${dump.endsWith("\n") ? "\n" : ""}`;
			}
			return dump;
		});
		text = text.replace(/(?:[0-9a-f]{16,200}\r?\n){1,100000}[0-9a-f]{0,200}|(?<![0-9a-z])[0-9a-f]{12,100000}(?![0-9a-z])/gi, (blob) => {
			const hex = blob.replace(/\s+/g, "");
			if (hex.length % 2) return blob;
			const decoded = decodeText(Buffer.from(hex, "hex"));
			const found = decoded && this.holdsSecret(decoded);
			return found ? `[secret: hex of ${found}]${/\n$/.test(blob) ? "\n" : ""}` : blob;
		});
		return text.replace(/(?:[A-Za-z0-9+/]{16,200}={0,2}(?:\\r)?(?:\\n|\r?\n)){1,100000}(?:[A-Za-z0-9+/]{0,200}={0,2}(?![\w+/=:-]))?|[A-Za-z0-9+/_-]{8,1000000}={0,2}/g, (blob) => {
			const decoded = decodeBase64(blob);
			const found = decoded && this.holdsSecret(decoded);
			return found ? `[secret: base64 of ${found}]${/\n$/.test(blob) ? "\n" : ""}` : blob;
		});
	}

	/**
	 * What the model gets instead of a tool's text output. `maskWhole` is for a read of a secret file
	 * or a command that prints one; `command` is the shell command that produced the output, if any.
	 * The extension and the test harness both go through here.
	 */
	scrub(text: string, cwd: string, maskWhole = false, fileName = "", command = ""): string {
		this.refresh(cwd);
		// UTF-16 text read as UTF-8 has a NUL after every character.
		if ((text.match(/\0/g)?.length ?? 0) > text.length * 0.25) text = text.replace(/\0/g, "");
		if (command && this.printsSecret(command)) {
			// The credential is the line that is a single token; messages around it stay.
			const label = `[secret: output of \`${command.trim().split(/\s+/).slice(0, 3).join(" ")}\`]`;
			text = text
				.split("\n")
				.map((line) => (/^\s*\S{6,}\s*$/.test(line) && !/^\p{L}+[.:!]?$/u.test(line.trim()) ? label : line))
				.join("\n");
		}
		if (command) {
			const printed = this.printedSecretFiles(command, cwd);
			if (printed.length) {
				maskWhole = true;
				if (printed.length === 1) fileName = basename(printed[0]);
			}
		}
		return this.redact(this.maskAttributedLines(maskWhole ? this.mask(text, fileName) : text, cwd));
	}

	/** Forgets the directory walk, so a secret file just written is picked up at the next refresh. */
	invalidate() {
		this.walkedAt = 0;
	}

	/**
	 * Brings the values up to date: re-reads changed secret files, and re-walks the project for new
	 * ones at most every 30 seconds (or right after `invalidate`).
	 */
	refresh(cwd: string) {
		let changed = false;
		if (cwd !== this.walkedCwd || Date.now() - this.walkedAt > 30_000) {
			const paths = new Set([...this.projectSecretFiles(cwd), ...this.homeSecretFiles()]);
			for (const path of this.files.keys()) {
				if (!paths.has(path)) {
					this.files.delete(path);
					changed = true;
				}
			}
			for (const path of paths) if (!this.files.has(path)) this.files.set(path, { mtimeMs: -1, size: -1, values: [] });
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
			this.files.set(path, { mtimeMs, size, values: stat?.isFile() ? fileValues(path, this.label(path, cwd)) : [] });
			changed = true;
		}
		if (changed || this.version === 0) this.rebuild();
	}

	private rebuild() {
		const labels = new Map<string, string>();
		const add = (value: string, label: string) => {
			for (const v of variants(value)) if (!labels.has(v)) labels.set(v, label);
		};
		for (const entry of this.files.values()) for (const [value, label] of entry.values) add(value, label);
		for (const [name, value] of Object.entries(process.env)) {
			if (!value) continue;
			for (const [v, l] of credentialsIn(name, value, `$${name}`)) add(v, l);
		}
		this.labels = labels;
		this.long = new LiteralIndex();
		this.ends = new LiteralIndex();
		this.endLabels = new Map();
		const short: string[] = [];
		for (const [v, label] of labels) {
			if (v.length >= 16) this.long.add(v);
			else short.push(v);
			// Only values long enough that a 16-character end is still unmistakably theirs.
			if (v.length >= 24 && /^[A-Za-z0-9+/=_-]+$/.test(v)) {
				for (const end of [v.slice(0, 16), v.slice(-16)]) {
					this.ends.add(end);
					if (!this.endLabels.has(end)) this.endLabels.set(end, label);
				}
			}
		}
		this.long.sort();
		this.ends.sort();
		// Short values only match as whole words; chunked so no single regex gets huge.
		const escape = (v: string) => v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
		short.sort((a, b) => b.length - a.length);
		this.short = [];
		for (let i = 0; i < short.length; i += 500) {
			// A short value matches only as a whole word, or straight after a flag like `-p`.
			this.short.push(new RegExp(`(?:(?<![\\p{L}\\p{N}])|(?<=[\\s'"]-[A-Za-z]))(?:${short.slice(i, i + 500).map(escape).join("|")})(?![\\p{L}\\p{N}])`, "gu"));
		}
		this.version++;
	}

	private label(path: string, cwd: string): string {
		const rel = relative(cwd, path);
		return rel.startsWith("..") || isAbsolute(rel) ? path.replace(this.home, "~") : rel;
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

// --- Reading values out of files ------------------------------------------------------------------

/**
 * The credentials inside one named value: the value itself under a credential name, the password of
 * a URL, credential parts of a connection string, nested JSON, and decoded base64.
 */
function credentialsIn(name: string, raw: string, label: string, depth = 0): [string, string][] {
	const value = cleanValue(raw);
	const out: [string, string][] = [];
	if (!value || depth > 3) return out;
	const credential = isCredentialName(name) || (isCredentialWhenRandom(name) && hasRandomToken(value));
	if (credential && isDistinctive(value)) out.push([value, label]);
	// `user/password` (NEO4J_AUTH) and `user:password` (BUNDLE_*, docker auth) under a credential name.
	const pair = credential && !isPath(value) && !/:\/\//.test(value) ? value.match(/^[\w.@-]{1,64}[/:]([^\s/]{6,})$/)?.[1] : undefined;
	if (pair && isDistinctive(pair)) out.push([pair, label]);
	for (const m of value.matchAll(/[a-z][a-z0-9+.-]{0,20}:\/\/[^\s/?#@:]{0,200}:([^\s]{1,300}?)@[^\s@/?#]{1,300}(?=[/?#:\s]|$)/gi)) {
		for (const v of new Set([m[1], safeDecodeURI(m[1])])) if (v.length >= 6 && !/^\p{L}+$/u.test(v) && !isInert(v)) out.push([v, label]);
	}
	for (const m of value.matchAll(/(?:^|;)[ \t]*([\w ]{1,60})=([^;]{1,500})/g)) if (m[1] !== name) out.push(...credentialsIn(m[1].trim(), m[2], label, depth + 1));
	if (/^[{[]/.test(value)) {
		try {
			for (const [k, v] of jsonPairs(JSON.parse(value))) out.push(...credentialsIn(k, v, label, depth + 1));
		} catch {}
	}
	if (credential && /^[A-Za-z0-9+/=_-]{8,}$/.test(value) && value.length % 4 === 0) {
		const decoded = decodeBase64(value);
		if (decoded && decoded !== value) {
			const pw = decoded.match(/^[^:\s]+:(.+)$/)?.[1];
			if (pw) {
				if (pw.length >= 6) out.push([pw, label]);
			} else if (isDistinctive(decoded.trim())) out.push([decoded.trim(), label]);
		}
	}
	return out;
}

function* jsonPairs(value: unknown, key = "", secretContext = false): Generator<[string, string]> {
	if (typeof value === "string") yield [secretContext && /^(value|result|private_key_\w+|bcrypt_hash)$/.test(key) ? "secret" : key, JSON.stringify(value)];
	else if (Array.isArray(value)) for (const v of value) yield* jsonPairs(v, key, secretContext);
	else if (value && typeof value === "object") {
		// `{"name": "password", "value": "…"}` and `{"label": …, "value": …}`: the name is a sibling.
		const record = value as Record<string, unknown>;
		// Terraform marks secrets: `"sensitive": true` outputs, and random_password/tls_private_key results.
		const secret = secretContext || record.sensitive === true || /^(random_password|tls_private_key|random_string)$/.test(String(record.type ?? ""));
		const sibling = ["name", "label", "key", "keyName", "Name", "Key"].map((k) => record[k]).find((v) => typeof v === "string") as string | undefined;
		for (const [k, v] of Object.entries(record)) yield* jsonPairs(v, /^value$/i.test(k) && sibling && !secret ? sibling : k, secret);
	}
}

function safeDecodeURI(value: string): string {
	try {
		return decodeURIComponent(value);
	} catch {
		return value;
	}
}

/** The secret values in a file, each with a label naming where it came from. */
function fileValues(path: string, where: string): [string, string][] {
	let text: string;
	try {
		if (statSync(path).size > 32 * 1024 * 1024) return [];
		text = readFileSync(path, "utf8");
	} catch {
		return [];
	}
	if ((text.match(/\0/g)?.length ?? 0) > text.length * 0.25) text = text.replace(/\0/g, "");
	const name = basename(path);
	const values: [string, string][] = [];
	const push = (value: string, label: string) => {
		if (value.length >= 6 && !isInert(value)) values.push([value, label]);
	};
	for (const block of text.match(/-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY( BLOCK)?-----[\s\S]{0,20000}?-----END [A-Z0-9 ]{0,40}PRIVATE KEY( BLOCK)?-----/g) ?? []) {
		push(block, where);
		for (const line of block.split("\n")) if (!line.startsWith("-----") && line.trim().length >= 16) push(line.trim(), where);
	}
	if (/^\s*[{[]/.test(text)) {
		try {
			for (const [k, v] of jsonPairs(JSON.parse(text))) for (const [value, label] of credentialsIn(k, v, `${where} ${k}`)) push(value, label);
			return values;
		} catch {}
	}
	// Which YAML documents are Secrets: only their data is registered whatever its name.
	const secretDocs = text.split(/\n---[ \t]*\r?\n/).map((doc) => /^[ \t-]*kind:[ \t]*Secret\b/m.test(doc));
	let docIndex = 0;
	let inData = false;
	let block: { indent: number; label: string; lines: string[] } | undefined;
	const flush = () => {
		if (block?.lines.length) push(block.lines.join("\n"), block.label);
		for (const l of block?.lines ?? []) if (l.length >= 8) push(l, block!.label);
		block = undefined;
	};
	for (const rawLine of text.split("\n")) {
		const line = rawLine.replace(/\r$/, "");
		const indent = line.match(/^[ \t]*/)![0].length;
		if (block) {
			if (line.trim() === "" || indent > block.indent) {
				if (line.trim()) block.lines.push(line.trim());
				continue;
			}
			flush();
		}
		if (name === ".pgpass") {
			const fields = line.split(/(?<!\\):/);
			if (fields.length >= 5) push(fields.slice(4).join(":"), `${where} password`);
			continue;
		}
		if (/netrc$/.test(name)) {
			for (const m of line.matchAll(/\b(password|account)[ \t]+(\S+)/g)) push(m[2], `${where} ${m[1]}`);
			continue;
		}
		if (/\.decrypt\.private\.php$/.test(name)) {
			for (const m of line.matchAll(/"((?:[^"\\\n]|\\.){8,4000})"/g)) push(m[1], `${where} key`);
			continue;
		}
		if (/htpasswd$/i.test(name)) {
			const hash = line.match(/^[^:#\s]{1,100}:(.+)$/)?.[1];
			if (hash) push(hash.trim(), `${where} password hash`);
			continue;
		}
		if (name === "cookies.txt") {
			const fields = line.split("\t");
			if (!line.startsWith("#") && fields.length >= 7) push(fields[6], `${where} ${fields[5]}`);
			continue;
		}
		if (/^---[ \t]*$/.test(line)) {
			docIndex++;
			inData = false;
		}
		if (secretDocs[docIndex]) {
			if (/^(data|stringData):[ \t]*$/.test(line)) inData = true;
			else if (/^\S/.test(line)) inData = false;
			else if (inData) {
				const m = line.match(/^[ \t]+([\w.-]+):[ \t]*(\S.*)$/);
				if (m) {
					const value = cleanValue(m[2]);
					if (isDistinctive(value)) push(value, `${where} ${m[1]}`);
					const decoded = decodeBase64(value);
					if (decoded && isDistinctive(decoded.trim())) {
						push(decoded.trim(), `${where} ${m[1]}`);
						for (const dl of decoded.split("\n")) {
							const kv = dl.match(KV_LINE);
							if (kv) for (const [v, l] of credentialsIn(kv[2], kv[4], `${where} ${kv[2]}`)) push(v, l);
						}
					}
				}
				continue;
			}
		}
		const blockStart = line.match(/^[ \t]*-?[ \t]*["']?([\w.-]{1,100})["']?[ \t]*:[ \t]*[|>][-+]?[ \t]*$/);
		if (blockStart && isCredentialName(blockStart[1])) {
			block = { indent, label: `${where} ${blockStart[1]}`, lines: [] };
			continue;
		}
		for (const m of line.matchAll(/<([\w:.-]{1,100})>([^<]{0,4000})<\/\1>/g)) for (const [value, label] of credentialsIn(m[1], m[2], `${where} ${m[1]}`)) push(value, label);
		// TOML inline tables and YAML flow mappings: several pairs on one line.
		for (const m of line.matchAll(/[{,][ \t]{0,10}["']?([\w.-]{1,80})["']?[ \t]{0,10}[=:][ \t]{0,10}("[^"\n]{0,500}"|'[^'\n]{0,500}'|[^,}\n]{1,500})/g)) {
			for (const [value, label] of credentialsIn(m[1], m[2], `${where} ${m[1]}`)) push(value, label);
		}
		const kv = line.match(KV_LINE);
		if (kv) {
			const label = `${where} ${kv[2].split(/[/:]/).filter(Boolean).at(-1)}`;
			for (const [value, l] of credentialsIn(kv[2], kv[4], label)) push(value, l);
			// Inside a secret file, `user:password` is a credential whatever the name is (~/.bundle/config).
			const hostPair = cleanValue(kv[4]).match(/^[\w.@-]{1,64}:([^\s/:]{6,})$/);
			if (hostPair && !/^\d{1,5}$/.test(hostPair[1]) && isDistinctive(hostPair[1])) push(hostPair[1], label);
			// A 32-byte hex key under any name, unless the name says it's an ID or a hash. Shorter hex is IDs and SHAs.
			const value = cleanValue(kv[4]);
			if (/^[0-9a-f]{64,}$/i.test(value) && !/(ID|SHA|HASH|COMMIT|REV|REVISION|FINGERPRINT|DIGEST|CHECKSUM|ETAG|VERSION)$/.test(words(kv[2]).at(-1) ?? "")) push(value, label);
		} else if (/^[ \t]{0,20}[a-z][\w.-]{1,60}[ \t]/.test(line)) {
			// A space-separated config line (redis.conf and friends), and Redis ACL passwords.
			const spaced = line.match(/^[ \t]{0,20}([a-z][\w.-]{1,60})[ \t]+([^=:\s].{0,2000})$/);
			if (spaced && isCredentialName(spaced[1])) push(cleanValue(spaced[2]), `${where} ${spaced[1]}`);
			for (const m of line.matchAll(/[ \t]>(\S{1,400})/g)) push(m[1], `${where} acl password`);
		} else {
			for (const m of line.matchAll(/[a-z][a-z0-9+.-]{0,20}:\/\/[^\s/?#@:]{0,200}:([^\s]{1,300}?)@[^\s@/?#]{1,300}(?=[/?#:\s]|$)/gi)) push(safeDecodeURI(m[1]), where);
			// A line that is only a value, as in .vault-token or a YAML list of keys.
			const bare = cleanValue(line.replace(/^[ \t]*-[ \t]+/, ""));
			if (isRandomToken(bare) || /^[0-9a-f]{64,}$/i.test(bare) || (/^[A-Za-z0-9+/=_.~!@#$%^&*-]{8,}$/.test(bare) && looksSecret(bare))) push(bare, where);
		}
	}
	flush();
	return values;
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

function isFile(path: string): boolean {
	try {
		return statSync(path).isFile();
	} catch {
		return false;
	}
}

/** Whether a known secret value can be replaced everywhere it appears (used by the test harness). */
export const isReplaceable = isDistinctive;
