/**
 * The secret cases hold synthetic values in real credential formats, because that is what they test.
 * Stored verbatim they would trip every secret scanner that sees this repository, so the case files
 * keep each format's prefix as a `@@NAME@@` marker and the harness puts the real prefix back on load.
 * Nothing about a value changes except how it sits at rest; pi-safety is handed the real string.
 *
 * `node test/secret-cases/encode.mjs` applies the markers to the case files; `--decode` reverses it.
 * A new case can be written with real prefixes and then encoded.
 */

/** Marker to literal. Longest literals first, so a prefix of another rule can't claim them. */
export const MARKERS: [string, string][] = [
	["@@PEM_BEGIN@@", "-----BEGIN "],
	["@@PEM_END@@", "-----END "],
	["@@GH_PAT@@", "github_pat_"],
	["@@GH_P@@", "ghp_"],
	["@@GH_O@@", "gho_"],
	["@@GH_U@@", "ghu_"],
	["@@GH_S@@", "ghs_"],
	["@@GH_R@@", "ghr_"],
	["@@GL_PAT@@", "glpat-"],
	["@@GL_DT@@", "gldt-"],
	["@@GL_SA@@", "glsa_"],
	["@@GL_C@@", "glc_"],
	["@@GOOG_OAUTH_ID@@", "apps.googleusercontent.com"],
	["@@GOOG_OAUTH_SECRET@@", "GOCSPX-"],
	["@@GOOG_API@@", "AIza"],
	["@@GOOG_TOKEN@@", "ya29."],
	["@@GOOG_REFRESH@@", "1//0"],
	["@@AWS_AKIA@@", "AKIA"],
	["@@AWS_ASIA@@", "ASIA"],
	["@@SK_ANT@@", "sk-ant-"],
	["@@SK_PROJ@@", "sk-proj-"],
	["@@SK_OR@@", "sk-or-v1-"],
	["@@SK_SVC@@", "sk-svcacct-"],
	["@@SK_DASH@@", "sk-"],
	["@@STRIPE_SK_LIVE@@", "sk_live_"],
	["@@STRIPE_SK_TEST@@", "sk_test_"],
	["@@STRIPE_RK_LIVE@@", "rk_live_"],
	["@@STRIPE_RK_TEST@@", "rk_test_"],
	["@@STRIPE_WHSEC@@", "whsec_"],
	["@@SLACK_WEBHOOK@@", "https://hooks.slack.com/services/"],
	["@@SLACK_XOXB@@", "xoxb-"],
	["@@SLACK_XOXP@@", "xoxp-"],
	["@@SLACK_XOXA@@", "xoxa-"],
	["@@SLACK_XOXS@@", "xoxs-"],
	["@@SLACK_XOXR@@", "xoxr-"],
	["@@SLACK_XAPP@@", "xapp-"],
	["@@SENDGRID@@", "SG."],
	["@@NPM@@", "npm_"],
	["@@PYPI@@", "pypi-AgE"],
	["@@DOCKER_PAT@@", "dckr_pat_"],
	["@@DO_PAT@@", "dop_v1_"],
	["@@DO_OAUTH@@", "doo_v1_"],
	["@@DO_REFRESH@@", "dor_v1_"],
	["@@HF@@", "hf_"],
	["@@SHOPIFY_AT@@", "shpat_"],
	["@@SHOPIFY_SS@@", "shpss_"],
	["@@SHOPIFY_CA@@", "shpca_"],
	["@@SHOPIFY_PA@@", "shppa_"],
	["@@VAULT_S@@", "hvs."],
	["@@VAULT_B@@", "hvb."],
	["@@VAULT_R@@", "hvr."],
	["@@AGE_SECRET@@", "AGE-SECRET-KEY-1"],
	["@@SUPABASE_P@@", "sbp_"],
	["@@SUPABASE_SECRET@@", "sb_secret_"],
	["@@DOPPLER_ST@@", "dp.st."],
	["@@DOPPLER_CT@@", "dp.ct."],
	["@@DOPPLER_SA@@", "dp.sa."],
	["@@TAILSCALE@@", "tskey-"],
	["@@HONEYCOMB@@", "hcaik_"],
	["@@NETLIFY@@", "nfp_"],
	["@@LINEAR@@", "lin_api_"],
	["@@POSTMAN@@", "PMAK-"],
	["@@ATLASSIAN@@", "ATATT3"],
	["@@ONEPASSWORD@@", "ops_eyJ"],
	["@@FLY_1@@", "fm1_"],
	["@@FLY_2@@", "fm2_"],
	["@@JWT@@", "eyJ"],
	["@@GL_CI_JOB@@", "glcbt-"],
	["@@HEROKU@@", "HRKU-"],
	["@@AIVEN@@", "AVNS_"],
	["@@GCP_SA_TYPE@@", "service_account"],
];

/**
 * Long runs are also stored in dotted chunks, so no contiguous credential-shaped token exists at
 * rest. Prefix markers alone don't satisfy scanners that work from entropy or a nearby keyword, and
 * the characters stay readable, unlike encrypting or hashing the corpus.
 */
const RUN = /[A-Za-z0-9+/]{20,}={0,2}/g;

/** Whether a run is the kind of thing a scanner reacts to, rather than a name or a sentence. */
function looksGenerated(run: string): boolean {
	return (/\d/.test(run) && /[A-Za-z]/.test(run)) || run.length >= 32;
}
const CHUNKED = /@@C:([A-Za-z0-9+/=_.-]{1,16000})@@/g;

/** Puts the real values back, so the cases run against the formats they describe. */
export function expandMarkers(text: string): string {
	text = text.replace(CHUNKED, (_m, chunks: string) => chunks.split(".").join(""));
	for (const [marker, literal] of MARKERS) text = text.split(marker).join(literal);
	return text;
}

/** Stores the values as prefix markers and dotted chunks. */
export function applyMarkers(text: string): string {
	for (const [marker, literal] of MARKERS) text = text.split(literal).join(marker);
	return text.replace(RUN, (run) => (looksGenerated(run) ? `@@C:${(run.match(/.{1,8}/g) ?? []).join(".")}@@` : run));
}
