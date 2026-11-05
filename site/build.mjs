// Build the page as one self-contained HTML file: the verifier bundle, the
// stylesheet and a sample are inlined, and the Content-Security-Policy admits
// exactly that script and that stylesheet by hash and nothing else. With
// default-src 'none' the browser refuses every network request the page could make.

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { build } from "esbuild";

const here = new URL("./", import.meta.url);
const root = new URL("../", import.meta.url);
const read = (base, path) => readFileSync(new URL(path, base));
const version = JSON.parse(read(root, "package.json").toString()).version;

const sample = {
  aof: read(root, "conformance/vectors/v0-lifecycle.jsonl").toString("base64"),
  heartbeat: read(root, "conformance/vectors/statement/heartbeat-at-4.json").toString("base64"),
  hubKey: "A87FVMoP1seBS9feyW1ZFf0VquP4QohMhwfqCnwK-Ss1",
  topic: "demo",
};

const bundle = await build({
  entryPoints: [new URL("page.ts", here).pathname],
  bundle: true,
  format: "iife",
  target: "es2022",
  minify: true,
  write: false,
  define: { SAMPLE: JSON.stringify(sample) },
});
const script = bundle.outputFiles[0].text;
const style = read(here, "page.css").toString();
for (const [name, text] of [["script", script], ["style", style]]) {
  if (text.toLowerCase().includes(`</${name}`)) throw new Error(`the ${name} contains a closing tag and cannot be inlined`);
}

const hash = (text) => `'sha256-${createHash("sha256").update(text).digest("base64")}'`;
const csp = `default-src 'none'; script-src ${hash(script)}; style-src ${hash(style)}; base-uri 'none'; form-action 'none'`;

const template = read(here, "index.html").toString();
const fill = (html, mark, value) => {
  if (html.split(mark).length !== 2) throw new Error(`the template must contain ${mark} exactly once`);
  return html.replace(mark, () => value);
};
let html = template;
html = fill(html, "__CSP__", csp);
html = fill(html, "/*STYLE*/", style);
html = fill(html, "/*SCRIPT*/", script);
html = fill(html, "__VERSION__", `Verifier ${version}`);

mkdirSync(new URL("dist/", here), { recursive: true });
writeFileSync(new URL("dist/index.html", here), html);
console.log(`site/dist/index.html: ${html.length} bytes`);
