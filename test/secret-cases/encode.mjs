/**
 * Applies the credential-prefix markers to the committed case files, so the repository holds no
 * string in a live credential format. `--decode` reverses it. See test/markers.ts.
 */
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { applyMarkers, expandMarkers } from "../markers.ts";

const dir = import.meta.dirname;
const decode = process.argv.includes("--decode");
for (const name of readdirSync(dir).filter((f) => f.endsWith(".json") && f !== "r2-robustness.json")) {
	const path = join(dir, name);
	const before = readFileSync(path, "utf8");
	const after = decode ? expandMarkers(before) : applyMarkers(expandMarkers(before));
	if (after !== before) {
		writeFileSync(path, after);
		console.log(`${decode ? "decoded" : "encoded"} ${name}`);
	}
}
