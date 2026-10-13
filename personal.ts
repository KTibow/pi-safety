/**
 * Personal data people paste into chats, which redac---n leaves alone: identity numbers, payment cards,
 * door codes and account recovery material. None of it is ever in a .env, so only patterns catch it. A
 * bare number is hidden only when a checksum or the issuing rules confirm it; after a label (`SSN:`,
 * `card number`) a mistyped one is hidden too, since 15 right digits of a card still leak it. Published
 * test numbers and examples stay, because tests and docs need them.
 *
 * Every regex here runs on untrusted output, so each is linear: bounded repetition, no `\s` across lines.
 */

/** Builds the text that replaces a value, from what it is and the value itself. */
export type Placeholder = (kind: string, value: string) => string;

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

/** Hides the personal data this module covers, labeled or confirmed by a checksum. */
export function redactPersonal(text: string, ph: Placeholder): string {
	text = redactBackupCodes(redactTotpKeys(text, ph), ph)
		// App passwords as Google and Apple print them: `abcd efgh ijkl mnop`, `abcd-efgh-ijkl-mnop`.
		.replace(new RegExp(String.raw`(\bpassword\b[^\n]{0,40}?[:\n]${SP}{0,3})([a-z]{4}(?:${SP}[a-z]{4}){3}|[a-z]{4}(?:-[a-z]{4}){3})(?![\w-])`, "gi"), (m, head, v) =>
			v === v.toLowerCase() ? `${head}${ph("app password", v)}` : m,
		);
	if (!/\d{3}/.test(text)) return text;
	text = text.replace(/[\uff10-\uff19]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 0xfee0)).replace(/(?<=\d)[\u00a0\u2010-\u2015](?=\d)/g, (c) => (c === "\u00a0" ? " " : "-"));
	const digits = (v: string) => v.replace(/\D/g, "");
	return text
		.replace(labeled(SSN_LABEL, String.raw`\d{3}[- .]?\d{2}[- .]?\d{4}`), (m, head, v) =>
			EXAMPLE_SSNS.has(digits(v)) || /^(\d)\1+$/.test(digits(v)) ? m : `${head}${ph("SSN", v)}`,
		)
		.replace(SSN, (m, a, b, c, offset: number, str: string) =>
			isIssuedSsn(a + b + c) && !ID_BEFORE.test(str.slice(Math.max(0, offset - 20), offset)) ? ph("SSN", m) : m,
		)
		.replace(labeled(CARD_LABEL, String.raw`\d[\d -]{11,22}\d`), (m, head, v) => {
			const d = digits(v);
			return d.length >= 13 && d.length <= 19 && !isTestCard(d) ? `${head}${ph("card number", v)}` : m;
		})
		.replace(CARD, (m, _a, _b, offset: number, str: string) => {
			const d = digits(m);
			return isCardNumber(d) && !isTestCard(d) && !ID_BEFORE.test(str.slice(Math.max(0, offset - 20), offset)) ? ph("card number", m) : m;
		})
		.replace(labeled(CVV_LABEL, String.raw`\d{3,4}`), (_m, head, v) => `${head}${ph("card security code", v)}`)
		.replace(labeled(CODE_LABEL, String.raw`[*#]?\d{4,10}[#*]?`), (m, head, v) => (DEFAULT_PINS.test(digits(v)) ? m : `${head}${ph("code", v)}`))
		.replace(labeled(PASSPORT_LABEL, String.raw`[A-Z0-9]{6,9}`), (m, head, v) => (/\d/.test(v) && v === v.toUpperCase() ? `${head}${ph("passport number", v)}` : m))
		.replace(labeled(LICENSE_LABEL, String.raw`[A-Z0-9](?:[A-Z0-9]|[ -](?=[A-Z0-9])){5,19}`), (m, head, v) =>
			(v.match(/\d/g)?.length ?? 0) >= 4 && v === v.toUpperCase() ? `${head}${ph("license number", v)}` : m,
		);
}

/** Base32 secrets printed in docs (Google Authenticator's wiki, RFC 6238), which aren't anyone's. */
const EXAMPLE_TOTP = /^(JBSWY3DPEHPK3PXP|GEZDGNBVGY3TQOJQ)/;

/**
 * Two-factor setup keys, the permanent seed behind every code an authenticator shows: base32, in
 * groups of four or run together, near the words that introduce one (`Can't scan? Enter this key`).
 * Hex-only groups are GPG fingerprints, not base32 keys.
 */
function redactTotpKeys(text: string, ph: Placeholder): string {
	if (!/key|secret|2fa|factor|mfa|otp|authenticator|code/i.test(text)) return text;
	const re = new RegExp(String.raw`(?:(?<=\\[nrt])|(?<![\w\\/+=-]))(?:[A-Z2-7]{4}(?:([ -])[A-Z2-7]{4}(?:\1[A-Z2-7]{4}){2,14})|[a-z2-7]{4}(?:([ -])[a-z2-7]{4}(?:\2[a-z2-7]{4}){2,14})|[A-Z2-7]{16,64})(?![\w/+=-])`, "g");
	return text.replace(re, (m, _a, _b, offset: number, str: string) => {
		const key = m.replace(/[ -]/g, "");
		const grouped = key !== m;
		if ((key.match(/[2-7]/g)?.length ?? 0) < (grouped ? 1 : 2) || /^[A-F2-7]+$/i.test(key) || EXAMPLE_TOTP.test(key.toUpperCase())) return m;
		const before = str.slice(Math.max(0, offset - 80), offset);
		const trigger = grouped ? /\b(key|secret|code|2fa|two[- ]factor|mfa|totp|otp|authenticator)\b/i : /\b(key|secret|2fa|two[- ]factor|mfa|totp|otp|authenticator)\b/i;
		return trigger.test(before) ? ph("2FA setup key", key) : m;
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
function redactBackupCodes(text: string, ph: Placeholder): string {
	if (!BACKUP_LABEL.test(text)) return text;
	const mask = (s: string) =>
		s.replace(BACKUP_CODE_RE, (code) => (code.length >= 6 && !/^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(code) ? ph("backup code", code) : code));
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
