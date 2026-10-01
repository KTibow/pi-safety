// Generates r2-robustness.json next to this file: 17 MB of large and pathological inputs, too big to
// commit. Synthetic values only (seeded PRNG). `pnpm eval:secrets` runs it first.
import { writeFileSync } from "node:fs";

let seed = 0x2f6b9a1d;
const rnd = () => {
	seed ^= seed << 13; seed >>>= 0;
	seed ^= seed >>> 17;
	seed ^= seed << 5; seed >>>= 0;
	return seed / 2 ** 32;
};
const bytes = (n) => Buffer.from(Array.from({ length: n }, () => (rnd() * 256) | 0));
const ALNUM = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
const tok = (n, alphabet = ALNUM) => Array.from({ length: n }, () => alphabet[(rnd() * alphabet.length) | 0]).join("");
const hex = (n) => bytes(n / 2).toString("hex");
const pem = (label, n) => `-----BEGIN ${label}-----\n${bytes(n).toString("base64").replace(/.{64}/g, "$&\n").replace(/\n$/, "")}\n-----END ${label}-----\n`;

const cases = [];
const add = (c) => cases.push(c);

// ---------------------------------------------------------------- SLOW: catastrophic backtracking

{
	// Jinja2 without trim_blocks: each skipped row of a {% for %}/{% if %} leaves whitespace-only lines.
	const rows = [];
	for (let i = 0; i < 70; i++) rows.push("                \n                    \n");
	const html = `<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Orders · Acme Admin</title>
    <link rel="stylesheet" href="/static/css/admin.css">
</head>
<body>
    <main class="container">
        <h1>Open orders</h1>
        <table class="table">
            <thead><tr><th>#</th><th>Customer</th><th>Total</th></tr></thead>
            <tbody>
${rows.join("")}                <tr><td>10482</td><td>Jane Doe</td><td>$48.20</td></tr>
${rows.join("")}            </tbody>
        </table>
    </main>
</body>
</html>
`;
	add({
		id: "jinja-whitespace-lines-html",
		why: "redactNamedValues' `name: value` regex starts `^(\\s*-?\\s*[\"']?)` under /gm: two adjacent \\s* that also match newlines make each run of whitespace-only lines cubic to reject (~280 indented blank lines, ~5 KB of HTML)",
		command: "curl -s http://localhost:5000/admin/orders",
		output: html,
		keep: ["<tr><td>10482</td><td>Jane Doe</td><td>$48.20</td></tr>", "<title>Orders · Acme Admin</title>"],
		maxMs: 200,
	});
}

{
	const lines = [];
	for (let i = 0; i < 600; i++) lines.push("\r\n");
	const out = `Microsoft (R) Build Engine version 17.8.3+195e7f5a3 for .NET\r\nCopyright (C) Microsoft Corporation. All rights reserved.\r\n${lines.join("")}  Determining projects to restore...\r\n  All projects are up-to-date for restore.\r\n  Acme.Api -> C:\\src\\acme\\Acme.Api\\bin\\Release\\net8.0\\Acme.Api.dll\r\n\r\nBuild succeeded.\r\n    0 Warning(s)\r\n    0 Error(s)\r\n`;
	add({
		id: "crlf-blank-lines-msbuild-log",
		why: "same `^(\\s*-?\\s*` regex: 600 consecutive CRLF blank lines (2 whitespace chars each) are already seconds of backtracking",
		command: "cat build/msbuild.log",
		output: out,
		keep: ["Build succeeded.", "Acme.Api -> C:\\src\\acme\\Acme.Api\\bin\\Release\\net8.0\\Acme.Api.dll"],
		maxMs: 200,
	});
}

{
	// Hardhat artifact: bytecode is "0x" + hex, so `\b[0-9a-f]{12,}\b` never matches and the first
	// alternative `[0-9a-f]{16,}\r?\n` rescans to the end of the run from every offset.
	const bytecode = "0x608060405234801561001057600080fd5b50" + hex(30000);
	const deployed = "0x6080604052348015600f57600080fd5b50" + hex(28000);
	const artifact = JSON.stringify(
		{
			_format: "hh-sol-artifact-1",
			contractName: "AcmeToken",
			sourceName: "contracts/AcmeToken.sol",
			abi: [
				{ inputs: [{ internalType: "address", name: "account", type: "address" }], name: "balanceOf", outputs: [{ internalType: "uint256", name: "", type: "uint256" }], stateMutability: "view", type: "function" },
			],
			bytecode,
			deployedBytecode: deployed,
			linkReferences: {},
			deployedLinkReferences: {},
		},
		null,
		2,
	);
	add({
		id: "hardhat-artifact-bytecode",
		why: "redactBlobs' hex regex `(?:[0-9a-f]{16,}\\r?\\n)+[0-9a-f]*|\\b[0-9a-f]{12,}\\b` is quadratic on a 0x-prefixed hex run (no \\b after the x): two contract bytecodes of ~60 KB hex",
		command: "cat artifacts/contracts/AcmeToken.sol/AcmeToken.json",
		output: artifact + "\n",
		keep: ['"contractName": "AcmeToken"', '"name": "balanceOf"', bytecode.slice(0, 200)],
		maxMs: 1000,
	});
}

// ---------------------------------------------------------------- SLOW: per-line filesystem calls

{
	const items = [];
	for (let i = 0; i < 26000; i++)
		items.push({
			id: 100000 + i,
			sku: `SKU-${(i * 7919) % 99991}`,
			name: `Product ${i}`,
			price: Math.round(rnd() * 10000) / 100,
			tags: ["catalog", i % 2 ? "outdoor" : "kitchen"],
			stock: { warehouse: "DAL-1", qty: (i * 31) % 500 },
		});
	add({
		id: "large-json-fixture-cat",
		why: "maskAttributedLines calls isSecret (realpathSync + statSync on a throwaway path) for every distinct line and every colon-prefix of it, so a 4 MB pretty JSON file costs ~200k syscalls",
		command: "cat fixtures/products.json",
		output: JSON.stringify(items, null, 2) + "\n",
		keep: ['"sku": "SKU-7919"', '"name": "Product 25999"'],
		maxMs: 1000,
	});
}

{
	const lines = [];
	for (let i = 0; i < 36000; i++) {
		const t = `2024-05-01T${String(8 + ((i / 3600) | 0)).padStart(2, "0")}:${String(((i / 60) | 0) % 60).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}.${String((i * 37) % 1000).padStart(3, "0")}Z`;
		lines.push(`${t}  INFO 1 --- [nio-8080-exec-${(i % 10) + 1}] c.acme.orders.web.RequestLogger         : GET /api/v1/orders/${200000 + i} status=200 duration=${i % 97}ms`);
	}
	add({
		id: "spring-boot-log-tail",
		why: "same per-line isSecret syscalls in maskAttributedLines: every timestamped log line has several colon prefixes, so a 5 MB log is thousands of realpathSync calls per MB",
		command: "tail -n 36000 logs/orders.log",
		output: lines.join("\n") + "\n",
		keep: ["GET /api/v1/orders/235999 status=200"],
		maxMs: 1000,
	});
}

// ---------------------------------------------------------------- SLOW / LEAK: known-value regex size

{
	const files = { "pki/vars": 'set_var EASYRSA_REQ_COUNTRY "US"\nset_var EASYRSA_KEY_SIZE 2048\n' };
	for (let i = 1; i <= 80; i++) files[`pki/private/client${String(i).padStart(3, "0")}.key`] = pem("PRIVATE KEY", 1218);
	files["pki/private/server.key"] = pem("PRIVATE KEY", 1218);
	add({
		id: "easy-rsa-pki-small-output",
		why: "rebuild() turns every 64-char line of every key into ~5 variants and joins them into one alternation; compiling that regex on the first scrub takes seconds with 81 RSA-2048 keys, for a 3-line output",
		files,
		command: "systemctl status openvpn-server@server --no-pager | head -3",
		output: "● openvpn-server@server.service - OpenVPN service for server\n     Loaded: loaded (/lib/systemd/system/openvpn-server@.service; enabled; preset: enabled)\n     Active: active (running) since Wed 2024-05-01 09:12:44 UTC; 3h 2min ago\n",
		keep: ["Active: active (running)"],
		maxMs: 1000,
	});
}

// ---------------------------------------------------------------- LEAK: size and count caps

{
	const resources = [];
	for (let i = 0; i < 2600; i++)
		resources.push({
			mode: "managed",
			type: "aws_route53_record",
			name: `svc_${i}`,
			provider: 'provider["registry.terraform.io/hashicorp/aws"]',
			instances: [{ schema_version: 2, attributes: { allow_overwrite: null, fqdn: `svc-${i}.internal.acme.io`, id: `Z0123456789ABCDEFGHIJ_svc-${i}.internal.acme.io_CNAME`, name: `svc-${i}.internal.acme.io`, records: [`lb-${i % 7}.internal.acme.io`], ttl: 300, type: "CNAME", zone_id: "Z0123456789ABCDEFGHIJ" }, sensitive_attributes: [] }],
		});
	const password = "q7Vt2#Lm9Xz4Rw8P";
	resources.push({
		mode: "managed",
		type: "aws_db_instance",
		name: "main",
		provider: 'provider["registry.terraform.io/hashicorp/aws"]',
		instances: [{ schema_version: 2, attributes: { address: "main.cx1abc2def3g.us-east-1.rds.amazonaws.com", engine: "postgres", engine_version: "16.2", identifier: "main", username: "acme", password, port: 5432 }, sensitive_attributes: [[{ type: "get_attr", value: "password" }]] }],
	});
	const state = JSON.stringify({ version: 4, terraform_version: "1.8.2", serial: 412, lineage: "4b1e7c2a-9d3f-4e8a-b6c1-2f7d9a0e5b13", outputs: { db_password: { value: password, type: "string", sensitive: true } }, resources, check_results: null }, null, 2);
	add({
		id: "tfstate-over-1mb-terraform-output",
		why: `fileValues() returns nothing for files over 1 MB, so a ${(state.length / 1e6).toFixed(1)} MB terraform.tfstate (2,600 DNS records) registers no values and \`terraform output -raw\` prints the database password untouched`,
		files: { "infra/terraform.tfstate": state },
		command: "cd infra && terraform output -raw db_password",
		output: password,
		hide: [password],
	});
}

{
	const docs = [];
	for (let i = 0; i < 700; i++)
		docs.push(`---
# Source: acme/templates/configmap-${i}.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: acme-feature-${i}
  labels:
    app.kubernetes.io/name: acme
    app.kubernetes.io/instance: prod
    helm.sh/chart: acme-3.4.1
data:
  FEATURE_NAME: "feature-${i}"
  ROLLOUT_PERCENT: "${i % 100}"
  OWNER_TEAM: "team-${i % 12}"
  DESCRIPTION: "Feature flag ${i} for the storefront, see https://wiki.acme.io/flags/${i}"
`);
	const password = "Vq7#mZ2!pLx9@Rt4";
	docs.push(`---
# Source: acme/templates/secret-db.yaml
apiVersion: v1
kind: Secret
metadata:
  name: acme-db
type: Opaque
data:
  username: ${Buffer.from("acme").toString("base64")}
  password: ${Buffer.from(password).toString("base64")}
`);
	const yaml = docs.join("");
	add({
		id: "rendered-manifest-over-256kb-secret",
		why: `isKubeSecret() skips YAML over 256 KB, so a ${(yaml.length / 1024) | 0} KB \`helm template\` render with a Secret at the end registers nothing and the decoded password reaches the model`,
		files: { "deploy/rendered/prod.yaml": yaml },
		command: "kubectl get secret acme-db -n prod -o jsonpath='{.data.password}' | base64 -d",
		output: password,
		hide: [password],
	});
}

{
	const files = {};
	const names = [];
	for (let i = 1; i <= 70; i++) names.push(`svc-${String(i).padStart(3, "0")}`);
	for (const n of names) {
		files[`packages/${n}/.env.development`] = `PORT=${3000 + names.indexOf(n)}\nLOG_LEVEL=debug\n`;
		files[`packages/${n}/.env.test`] = `PORT=${4000 + names.indexOf(n)}\nLOG_LEVEL=warn\n`;
		files[`packages/${n}/.env.production`] = `PORT=8080\nLOG_LEVEL=info\n`;
	}
	const hook = "whsec_7pQ2vK9mXz4Lt8Rw3Nc6Yb1H";
	files["packages/svc-070/.env.production"] = `PORT=8080\nLOG_LEVEL=info\nSTRIPE_WEBHOOK_SECRET=${hook}\n`;
	add({
		id: "monorepo-over-200-secret-files",
		why: "projectSecretFiles() stops after 200 secret files, so in a 70-package monorepo with three .env files each, the last package's webhook secret is never registered",
		files,
		command: "git log -p -1 -- packages/svc-070/src/webhooks.ts",
		output: `commit 9c1f2e7a4b3d8c6e5f0a1b2c3d4e5f6a7b8c9d0e\nAuthor: Dev <dev@acme.io>\nDate:   Wed May 1 10:12:44 2024 +0000\n\n    temp: hardcode webhook secret for local replay\n\ndiff --git a/packages/svc-070/src/webhooks.ts b/packages/svc-070/src/webhooks.ts\n--- a/packages/svc-070/src/webhooks.ts\n+++ b/packages/svc-070/src/webhooks.ts\n@@ -3,3 +3,3 @@\n-const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;\n+const endpointSecret = "${hook}";\n const event = stripe.webhooks.constructEvent(body, sig, endpointSecret);\n`,
		hide: [hook],
		keep: ["const event = stripe.webhooks.constructEvent(body, sig, endpointSecret);"],
	});
}

// ---------------------------------------------------------------- LEAK: line prefixes, encodings, unicode

{
	const key = pem("RSA PRIVATE KEY", 1190);
	const keyLines = key.trim().split("\n");
	const values = `ingress:\n  enabled: true\n  hosts:\n    - shop.acme.io\n  tls:\n    crt: |\n      -----BEGIN CERTIFICATE-----\n      MIIBszCCAVmgAwIBAgIUQk\n      -----END CERTIFICATE-----\n    key: |\n${keyLines.map((l) => `      ${l}`).join("\n")}\n`;
	const start = values.split("\n").findIndex((l) => l.includes("BEGIN RSA PRIVATE KEY"));
	const out = values
		.split("\n")
		.slice(start, start + keyLines.length)
		.map((l, i) => `charts/shop/values.yaml${i === 0 ? ":" : "-"}${start + 1 + i}${i === 0 ? ":" : "-"}${l}`)
		.join("\n");
	add({
		id: "grep-context-private-key",
		why: "redactPrivateKeys' line loop only continues over lines that are bare base64, so `path-12-` grep prefixes stop it at the BEGIN line; values.yaml isn't a secret file, so nothing else catches the key",
		command: 'grep -rn -A30 "BEGIN RSA PRIVATE KEY" charts/',
		output: out + "\n",
		hide: [keyLines[1], keyLines[5], keyLines[10]],
		keep: ["charts/shop/values.yaml:"],
	});
}

{
	const raw = pem("PRIVATE KEY", 900).trim().split("\n").join("\r\n") + "\r\n";
	const keyLine = raw.split("\r\n")[3];
	const json = JSON.stringify({ Logging: { LogLevel: { Default: "Information" } }, Jwt: { Issuer: "https://id.acme.io", Audience: "acme-api", SigningPem: raw } });
	add({
		id: "minified-json-crlf-escaped-pem",
		why: "the JSON branch of redactPrivateKeys only follows `\\n` escapes, and the line loop needs a following line, so a PEM saved on Windows (`\\r\\n` escapes) inside single-line JSON with no trailing newline (curl) is never replaced",
		command: "curl -s http://localhost:5080/debug/config",
		output: json,
		hide: [keyLine],
		keep: ['"Issuer":"https://id.acme.io"', '"Default":"Information"'],
	});
}

{
	const at = "Zq8vN3kLx7RtP2mWc9YbH4sJ";
	const rt = "Lp4Xw9TzK2vQ8mRn5JcB7yHd";
	add({
		id: "oauth-token-response-minified",
		why: "redactNamedValues only recognizes `name: value` at the start of a line, so credential-named fields of single-line JSON (any API response) pass through when their values have no known token format",
		command: "curl -s -X POST https://auth.acme.io/oauth/token -d grant_type=client_credentials -d client_id=reporting",
		output: `{"access_token":"${at}","token_type":"Bearer","expires_in":3600,"refresh_token":"${rt}","scope":"reports:read"}`,
		hide: [at, rt],
		keep: ['"expires_in":3600', '"scope":"reports:read"'],
	});
}

{
	const key = "Hq7vT2mX9pLw4Rz8";
	const tokenv = "m4Kx8Vb2Qz7Lp9Nt";
	add({
		id: "cjk-log-fullwidth-colon",
		why: "the `NAME=value` rule only starts after ASCII whitespace, quotes, comma, [ or ;, so a full-width colon or CJK bracket before the name (Chinese log lines) hides nothing",
		command: "kubectl logs deploy/order-svc -n prod --tail=3",
		output: `2024-05-01 10:00:00.120 [main] INFO  启动参数：DB_PASSWORD=${key} REDIS_HOST=cache-0\n2024-05-01 10:00:00.124 [main] INFO  【配置】API_TOKEN=${tokenv}\n2024-05-01 10:00:01.002 [main] INFO  服务已启动，端口 8080\n`,
		hide: [key, tokenv],
		keep: ["REDIS_HOST=cache-0", "服务已启动，端口 8080"],
	});
}

{
	const value = "Zq8vN3kLx7RtP2mW";
	const text = `NODE_ENV=production\r\nAPI_KEY=${value}\r\n`;
	const utf16 = [...text].map((c) => c + "\0").join("");
	add({
		id: "powershell-utf16-dotenv-read",
		why: "`echo ... > .env` in Windows PowerShell 5 writes UTF-16LE; read as UTF-8 every character is followed by NUL, so KV_LINE, the name rule and fileValues all miss the line and the key reaches the model unmasked",
		files: { ".env": utf16 },
		read: ".env",
		hide: [[...value].map((c) => c + "\0").join("").slice(0, -1)],
	});
}

{
	const env = `APP_ENV=production\nDB_HOST=db.internal.acme.io\nDB_PASSWORD=Gx7#vQ2mLp9Rt4Wz\nSTRIPE_WEBHOOK_SECRET=whsec_Lt8Rw3Nc6Yb1H7pQ2vK9mXz4\nSENTRY_DSN=https://3f9a2c7e1d8b4f6a@o4507.ingest.sentry.io/4507123\nMAIL_FROM=noreply@acme.io\n`;
	const b64 = Buffer.from(env).toString("base64").replace(/.{60}/g, "$&\n");
	const segs = b64.trim().split("\n");
	const out = `{
  "name": ".env.production",
  "path": ".env.production",
  "sha": "a7c3e9f1b2d4c6e8f0a1b3c5d7e9f1a2b4c6d8e0",
  "size": ${env.length},
  "type": "file",
  "content": "${segs.join("\\n")}\\n",
  "encoding": "base64"
}
`;
	add({
		id: "gh-api-contents-escaped-newlines",
		why: "the GitHub contents API wraps base64 at 60 chars with JSON `\\n` escapes; the base64 regex counts the `n` of each escape as data, so every chunk after the first decodes misaligned and the known .env values inside go through",
		files: { ".env.production": env },
		command: "gh api repos/acme/shop/contents/.env.production",
		output: out,
		// Only chunks after the first whose 45 decoded bytes hold 8+ characters of a credential value.
		hide: segs.slice(1).filter((seg) => {
			const d = Buffer.from(seg, "base64").toString("utf8");
			return ["Gx7#vQ2mLp9Rt4Wz", "whsec_Lt8Rw3Nc6Yb1H7pQ2vK9mXz4"].some((v) => [...Array(v.length - 7).keys()].some((i) => d.includes(v.slice(i, i + 8))));
		}),
		keep: ['"encoding": "base64"', '"path": ".env.production"'],
	});
}

// ---------------------------------------------------------------- LOST: non-ASCII plain words

add({
	id: "spanish-dev-password-word",
	why: "isDistinctive() treats only ASCII words as plain words, so a dev password like `contraseña` is replaced in all output, including Spanish UI strings",
	files: { ".env": "NODE_ENV=development\nDB_USER=app\nDB_PASSWORD=contraseña\n" },
	command: "cat src/locales/es.json",
	output: '{\n  "login.title": "Iniciar sesión",\n  "login.password": "Introduce tu contraseña",\n  "login.forgot": "¿Olvidaste tu contraseña?"\n}\n',
	keep: ["Introduce tu contraseña", "¿Olvidaste tu contraseña?"],
});

add({
	id: "russian-dev-password-word",
	why: "same: `пароль` (\"password\") as a local DB password is registered as distinctive and replaced in every Russian message bundle",
	files: { ".env": "SPRING_PROFILES_ACTIVE=dev\nSPRING_DATASOURCE_PASSWORD=пароль\n" },
	command: "cat src/main/resources/messages_ru.properties",
	output: "login.title=Вход\nlogin.password=Введите пароль\nlogin.error=Неверный логин или пароль\n",
	keep: ["login.password=Введите пароль", "login.error=Неверный логин или пароль"],
});

// ---------------------------------------------------------------- Regression guards (expected to pass)

{
	let js = "";
	let i = 0;
	while (js.length < 1_000_000) {
		js += `function(e,t,n){"use strict";var r=n(${i % 997}),o=n.n(r),i=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e};t.a=function(e){return o.a.createElement("div",i({className:"btn-${i % 31}"},e))}},`;
		i++;
	}
	add({
		id: "minified-bundle-1mb-single-line",
		why: "guard: a 1 MB single-line webpack bundle with no secrets passes through intact and fast",
		files: { ".env": `NEXT_PUBLIC_API_URL=https://api.acme.io\nSTRIPE_SECRET_KEY=sk_live_${tok(32)}\n` },
		command: "cat .next/static/chunks/main-3f9a2c7e.js",
		output: js,
		keep: [js.slice(500_000, 500_300), 'className:"btn-30"'],
		maxMs: 1000,
	});
}

{
	const lines = ["NODE_ENV=production", "PORT=8080"];
	const hidden = [];
	for (let i = 0; i < 2000; i++) {
		if (i % 4 === 0) {
			const v = tok(24);
			lines.push(`TENANT_${i}_API_KEY=${v}`);
			if (hidden.length < 5) hidden.push(v);
		} else if (i % 4 === 1) lines.push(`TENANT_${i}_REGION=us-east-${(i % 2) + 1}`);
		else if (i % 4 === 2) lines.push(`TENANT_${i}_WEBHOOK_URL=https://hooks.acme.io/t/${i}`);
		else lines.push(`TENANT_${i}_RATE_LIMIT=${100 + (i % 900)}`);
	}
	add({
		id: "dotenv-2000-entries-read",
		why: "guard: a .env with 2,000 entries is masked correctly and quickly",
		files: { ".env": lines.join("\n") + "\n" },
		read: ".env",
		hide: hidden,
		keep: ["NODE_ENV=production", "TENANT_1_REGION=us-east-2", "TENANT_2_WEBHOOK_URL=https://hooks.acme.io/t/2"],
		maxMs: 1000,
	});
}

{
	const env = { PATH: "/usr/local/bin:/usr/bin:/bin", HOME: "/home/runner", LANG: "C.UTF-8" };
	const hidden = [];
	for (let i = 0; i < 300; i++) {
		if (i % 3 === 0) {
			const v = tok(28);
			env[`SVC${i}_TOKEN`] = v;
			if (hidden.length < 6) hidden.push(v);
		} else env[`SVC${i}_HOST`] = `svc${i}.internal`;
	}
	const out = Object.entries(env).map(([k, v]) => `${k}=${v}`).join("\n") + "\n";
	add({
		id: "printenv-300-vars",
		why: "guard: 300 environment variables (100 credentials) are all registered and replaced, and harmless ones kept, fast",
		env: Object.fromEntries(Object.entries(env).filter(([k]) => k !== "PATH" && k !== "HOME")),
		command: "printenv",
		output: out,
		hide: hidden,
		keep: ["LANG=C.UTF-8", "SVC1_HOST=svc1.internal", "SVC299_HOST=svc299.internal"],
		maxMs: 1000,
	});
}

{
	const blob = bytes(600_000).toString("base64").replace(/.{76}/g, "$&\n");
	add({
		id: "base64-wasm-800kb",
		why: "guard: `base64` of an 600 KB binary, wrapped at 76, with secrets registered, decodes to binary and is kept fast",
		files: { ".env": `JWT_SECRET=${tok(40)}\n` },
		command: "base64 public/app.wasm",
		output: blob,
		keep: [blob.slice(400_000, 400_076)],
		maxMs: 1000,
	});
}

{
	const buf = bytes(200_000);
	const rows = [];
	for (let i = 0; i < buf.length; i += 16) {
		const c = buf.subarray(i, i + 16);
		rows.push(`${i.toString(16).padStart(8, "0")}: ${c.toString("hex").replace(/(....)/g, "$1 ").trim()}  ${[...c].map((b) => (b > 31 && b < 127 ? String.fromCharCode(b) : ".")).join("")}`);
	}
	add({
		id: "xxd-binary-200kb",
		why: "guard: an xxd dump of a random binary is kept and fast",
		files: { ".env": `JWT_SECRET=${tok(40)}\n` },
		command: "xxd assets/logo.bin",
		output: rows.join("\n") + "\n",
		keep: [rows[5000]],
		maxMs: 1000,
	});
}

add({
	id: "bom-crlf-dotenv-read",
	why: "guard: Notepad's UTF-8 BOM plus CRLF line endings on a .env",
	files: { ".env": "\ufeffAPI_KEY=Hq7vT2mX9pLw4Rz8\r\nNODE_ENV=production\r\nTZ=Europe/Berlin\r\n" },
	read: ".env",
	hide: ["Hq7vT2mX9pLw4Rz8"],
	keep: ["NODE_ENV=production", "TZ=Europe/Berlin"],
	maxMs: 200,
});

{
	let nested = { db: { host: "db.internal", password: "Rk8#vM3qZx7Lp2Wt" } };
	for (let i = 0; i < 40; i++) nested = { [`layer${i}`]: nested, [`name${i}`]: `tier-${i}` };
	add({
		id: "deeply-nested-secrets-json-read",
		why: "guard: secrets.json nested 40 levels deep is masked by name at the leaf and its harmless siblings kept",
		files: { "config/secrets.json": JSON.stringify(nested, null, 2) },
		read: "config/secrets.json",
		hide: ["Rk8#vM3qZx7Lp2Wt"],
		keep: ['"host": "db.internal"', '"name0": "tier-0"'],
		maxMs: 200,
	});
}

add({
	id: "token-formats-next-to-unicode",
	why: "guard: known token formats adjacent to emoji, CJK and full-width punctuation are still caught (\\b treats non-ASCII as non-word)",
	command: "cat notes/rotation.md",
	output: `# 轮换记录\n- 🔑ghp_${tok(36)}（旧）\n- 新密钥：sk-proj-${tok(40)}\n- Ключ:AKIA${tok(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")}\n`,
	hide: [],
	keep: ["# 轮换记录", "（旧）"],
	maxMs: 200,
});
// fill hide for the case above from its own output
{
	const c = cases.at(-1);
	c.hide = [...c.output.matchAll(/ghp_\w+|sk-proj-\w+|AKIA\w+/g)].map((m) => m[0]);
}

writeFileSync(new URL("./r2-robustness.json", import.meta.url), JSON.stringify(cases, null, 1));
console.log(cases.length, "cases");
