// The page: read a dropped file, run the verifier on it, draw the report.
// Everything is drawn with textContent, so a file's contents are never markup.

import { compareHeartbeats, verifyAof, type AofReport, type HeartbeatReport, type LineReport } from "../src/index.js";

declare const SAMPLE: { aof: string; heartbeat: string; hubKey: string; topic: string };

const MAX_ROWS = 2000;

function element<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (found === null) throw new Error(`missing element #${id}`);
  return found as T;
}

const drop = element<HTMLDivElement>("aof-drop");
const aofFile = element<HTMLInputElement>("aof-file");
const aofName = element<HTMLParagraphElement>("aof-name");
const heartbeatFile = element<HTMLInputElement>("heartbeat-file");
const hubKey = element<HTMLInputElement>("hub-key");
const topicId = element<HTMLInputElement>("topic-id");
const freshness = element<HTMLInputElement>("freshness");
const report = element<HTMLElement>("report");
const summary = element<HTMLDivElement>("report-summary");
const heartbeatSummary = element<HTMLDivElement>("heartbeat-report");
const note = element<HTMLParagraphElement>("report-note");
const body = element<HTMLTableSectionElement>("line-report-body");

let aofBytes: Uint8Array | null = null;
let heartbeatBytes: Uint8Array | null = null;

function fromBase64(text: string): Uint8Array {
  return Uint8Array.from(atob(text), (char) => char.charCodeAt(0));
}

function setSummary(target: HTMLElement, tone: "ok" | "bad" | "warn", title: string, lines: string[]): void {
  target.className = `summary ${tone}`;
  target.replaceChildren();
  const strong = document.createElement("strong");
  strong.textContent = title;
  target.append(strong);
  for (const line of lines) {
    const span = document.createElement("span");
    span.textContent = line;
    target.append(span);
  }
  target.hidden = false;
}

function describeMint(line: LineReport): string {
  const mint = line.mint;
  if (mint === undefined) return "";
  const target = mint.targetLine === null ? "Mint: no earlier valid entry has the target hash, so it confirms nothing" : `Mint: confirms line ${mint.targetLine}`;
  if (mint.flags === undefined) return target;
  const flag = (name: string, set: boolean) => `${name}=${set ? 1 : 0}`;
  return `${target} · ${flag("UV", mint.flags.userVerified)} ${flag("BE", mint.flags.backupEligible)} ${flag("BS", mint.flags.backupState)}`;
}

function row(line: LineReport): HTMLTableRowElement {
  const tr = document.createElement("tr");
  const cell = (className: string, text: string) => {
    const td = document.createElement("td");
    td.className = className;
    td.textContent = text;
    tr.append(td);
    return td;
  };
  cell("number", String(line.line));
  const badge = document.createElement("span");
  badge.className = `badge ${line.outcome === "valid" ? "ok" : "bad"}`;
  badge.textContent = line.outcome;
  cell("outcome", "").append(badge);
  cell("event-id", line.eventId ?? "");
  const extraFaults = line.faults.length > 1 ? `also: ${line.faults.slice(1).join(", ")}` : "";
  cell("detail", [line.detail ?? "", extraFaults, describeMint(line)].filter((part) => part !== "").join(" · "));
  return tr;
}

function drawAof(result: AofReport): void {
  const count = result.lines.length;
  const last = result.lines[count - 1];
  if (result.outcome === "valid") {
    const head = last?.eventId === undefined ? [] : [`Head (Event ID of the last entry): ${last.eventId}`];
    setSummary(summary, "ok", `Valid: ${count} ${count === 1 ? "entry" : "entries"}`, [
      "Every line is well formed, names the line before it, and is signed by the key it carries.",
      ...head,
    ]);
  } else if (result.rejectedAtLine !== undefined) {
    setSummary(summary, "bad", `Rejected at line ${result.rejectedAtLine}`, [
      `Line ${result.rejectedAtLine} is malformed: ${last?.detail ?? ""}. A malformed line rejects the whole file, so later lines were not read.`,
    ]);
  } else {
    const faulty = result.lines.filter((line) => line.outcome !== "valid");
    setSummary(summary, "bad", `Invalid: ${faulty.length} of ${count} lines failed`, [`First failure: line ${faulty[0]!.line}, ${faulty[0]!.outcome}.`]);
  }

  const failing = result.lines.filter((line) => line.outcome !== "valid");
  const shown = count <= MAX_ROWS ? result.lines : [...new Set([...result.lines.slice(0, MAX_ROWS), ...failing])];
  note.hidden = count <= MAX_ROWS;
  note.textContent = count <= MAX_ROWS ? "" : `Showing the first ${MAX_ROWS} lines and every line that failed, of ${count}.`;
  body.replaceChildren(...shown.map(row));
}

const HEARTBEAT_TITLES: Record<HeartbeatReport["outcome"], [tone: "ok" | "bad" | "warn", title: string]> = {
  match: ["ok", "Heartbeat: match"],
  missing: ["warn", "Heartbeat: missing"],
  stale: ["warn", "Heartbeat: stale"],
  conflicting: ["bad", "Heartbeat: conflicting"],
  short: ["warn", "Heartbeat: this copy is short"],
  not_compared: ["bad", "Heartbeat: not compared"],
};

function drawHeartbeat(result: AofReport): void {
  heartbeatSummary.hidden = true;
  const key = hubKey.value.trim();
  const topic = topicId.value;
  const window = freshness.value.trim();
  if (heartbeatBytes === null && key === "" && topic === "") return;
  if (key === "" || topic === "") {
    setSummary(heartbeatSummary, "warn", "Heartbeat: not checked", ["Enter both the Hub key and the topic. A heartbeat carries neither proof of the key nor the agreed topic."]);
    return;
  }
  try {
    const outcome = compareHeartbeats({
      aof: result,
      heartbeats: heartbeatBytes,
      hubKey: key,
      topicId: topic,
      freshnessSeconds: window === "" ? undefined : window,
      now: window === "" ? undefined : Math.floor(Date.now() / 1000).toString(),
    });
    const [tone, title] = HEARTBEAT_TITLES[outcome.outcome];
    const rejected = outcome.heartbeats.filter((item) => !item.authenticated).map((item) => `Heartbeat ${item.index + 1} does not count: ${item.reason}.`);
    const fresh = outcome.freshness === "not_assessed" ? "Freshness was not assessed: no window was given." : `Freshness: ${outcome.freshness}.`;
    setSummary(heartbeatSummary, tone, title, [`${outcome.detail[0]!.toUpperCase()}${outcome.detail.slice(1)}.`, ...rejected, ...(outcome.coveredPosition === undefined ? [] : [fresh])]);
  } catch (error) {
    setSummary(heartbeatSummary, "warn", "Heartbeat: not checked", [error instanceof Error ? error.message : String(error)]);
  }
}

function run(): void {
  if (aofBytes === null) return;
  const result = verifyAof(aofBytes);
  drawAof(result);
  drawHeartbeat(result);
  report.hidden = false;
}

async function takeAof(file: File): Promise<void> {
  aofBytes = new Uint8Array(await file.arrayBuffer());
  aofName.textContent = `${file.name} · ${aofBytes.length} bytes`;
  run();
}

function loadSample(): void {
  aofBytes = fromBase64(SAMPLE.aof);
  heartbeatBytes = fromBase64(SAMPLE.heartbeat);
  heartbeatFile.value = "";
  hubKey.value = SAMPLE.hubKey;
  topicId.value = SAMPLE.topic;
  freshness.value = "";
  aofName.textContent = `sample: four entries and one heartbeat · ${aofBytes.length} bytes`;
  run();
}

drop.addEventListener("dragover", (event) => {
  event.preventDefault();
  drop.classList.add("over");
});
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (event) => {
  event.preventDefault();
  drop.classList.remove("over");
  const file = event.dataTransfer?.files[0];
  if (file !== undefined) void takeAof(file);
});
drop.addEventListener("keydown", (event) => {
  if (event.target === drop && (event.key === "Enter" || event.key === " ")) {
    event.preventDefault();
    aofFile.click();
  }
});
aofFile.addEventListener("change", () => {
  const file = aofFile.files?.[0];
  if (file !== undefined) void takeAof(file);
});
heartbeatFile.addEventListener("change", async () => {
  const file = heartbeatFile.files?.[0];
  heartbeatBytes = file === undefined ? null : new Uint8Array(await file.arrayBuffer());
  run();
});
for (const input of [hubKey, topicId, freshness]) input.addEventListener("input", run);
element<HTMLButtonElement>("load-sample").addEventListener("click", loadSample);
if (location.hash === "#sample") loadSample();
