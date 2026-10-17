// Minimal agent harness for the coatcheck examples.
//
// One loop, one tool (Anthropic's bash tool), run inside a container whose only
// way out is the coatcheck proxy. The harness never holds a real secret either:
// its own Anthropic API key is a coatcheck ticket, re-minted before every call
// and swapped for the real key on the wire to api.anthropic.com.
//
// Usage: node src/agent.ts <task.md>   (Node >= 24 runs the .ts directly)
//
// Env: COATCHECK_URL (http://coatcheck:3128), COATCHECK_API_TOKEN,
//      HTTPS_PROXY / NODE_USE_ENV_PROXY=1 (set by the compose file),
//      AGENT_MODEL (default claude-opus-5-5), AGENT_MAX_TURNS (default 30),
//      AGENT_TRANSCRIPT (optional path for a JSON transcript).
import Anthropic from "@anthropic-ai/sdk";
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const COATCHECK_URL = process.env.COATCHECK_URL ?? "http://127.0.0.1:3128";
const API_TOKEN = process.env.COATCHECK_API_TOKEN;
const MODEL = process.env.AGENT_MODEL ?? "claude-opus-5-5";
const MAX_TURNS = Number(process.env.AGENT_MAX_TURNS ?? 30);
const COMMAND_TIMEOUT_MS = 120_000;
const MAX_OUTPUT_CHARS = 20_000;

const taskPath = process.argv[2];
if (!taskPath) {
  console.error("usage: node src/agent.ts <task.md>");
  process.exit(2);
}
const task = readFileSync(taskPath, "utf8");
const system = readFileSync(new URL("../system.md", import.meta.url), "utf8");

/** Mint a ticket for a named secret. The harness sees only the ticket. */
async function ticket(name: string): Promise<string> {
  const res = await fetch(`${COATCHECK_URL}/_vault/${encodeURIComponent(name)}`, {
    headers: API_TOKEN ? { Authorization: `Bearer ${API_TOKEN}` } : {},
  });
  const body = (await res.json()) as { token?: string; error?: string };
  if (!res.ok || !body.token) {
    throw new Error(`coatcheck refused ticket for '${name}': ${res.status} ${body.error ?? ""}`);
  }
  return body.token;
}

/** Run one command in a fresh bash shell, in the container's /work directory. */
function runBash(command: string): Promise<{ output: string; isError: boolean }> {
  return new Promise((resolve) => {
    const child = spawn("bash", ["-lc", command], { cwd: "/work", env: process.env });
    let output = "";
    const append = (chunk: Buffer) => {
      output += chunk.toString("utf8");
    };
    child.stdout.on("data", append);
    child.stderr.on("data", append);
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      output += `\n[killed after ${COMMAND_TIMEOUT_MS / 1000}s]`;
    }, COMMAND_TIMEOUT_MS);
    child.on("close", (code) => {
      clearTimeout(timer);
      if (output.length > MAX_OUTPUT_CHARS) {
        output = `${output.slice(0, MAX_OUTPUT_CHARS)}\n[truncated ${output.length - MAX_OUTPUT_CHARS} chars]`;
      }
      resolve({ output: output || `(exit ${code}, no output)`, isError: code !== 0 });
    });
  });
}

const indent = (s: string) => s.replace(/^/gm, "    ");
const messages: Anthropic.Beta.BetaMessageParam[] = [{ role: "user", content: task }];

for (let turn = 1; turn <= MAX_TURNS; turn++) {
  // Tickets live 15 minutes; minting one per call keeps long runs alive.
  const client = new Anthropic({ apiKey: await ticket("anthropic-api-key") });
  const response = await client.beta.messages.create({
    model: MODEL,
    max_tokens: 16000,
    betas: ["server-side-fallback-2026-07-01"],
    fallbacks: "default",
    output_config: { effort: "high" },
    system,
    tools: [{ type: "bash_20250124", name: "bash" }],
    messages,
  });
  messages.push({ role: "assistant", content: response.content });

  for (const block of response.content) {
    if (block.type === "text" && block.text.trim()) console.log(`\n[agent] ${block.text}`);
  }
  if (response.stop_reason === "refusal") {
    console.log(`\n[harness] model refused: ${response.stop_details?.category ?? "unknown"}`);
    break;
  }
  if (response.stop_reason !== "tool_use") break;

  const results: Anthropic.Beta.BetaToolResultBlockParam[] = [];
  for (const block of response.content) {
    if (block.type !== "tool_use") continue;
    const input = block.input as { command?: string; restart?: boolean };
    if (input.restart) {
      results.push({ type: "tool_result", tool_use_id: block.id, content: "Each command already runs in a fresh shell." });
      continue;
    }
    const command = input.command ?? "";
    console.log(`\n[bash] $ ${command}`);
    const { output, isError } = await runBash(command);
    console.log(indent(output.length > 2000 ? `${output.slice(0, 2000)}\n[… ${output.length - 2000} more chars]` : output));
    results.push({ type: "tool_result", tool_use_id: block.id, content: output, is_error: isError });
  }
  messages.push({ role: "user", content: results });
  if (turn === MAX_TURNS) console.log(`\n[harness] stopped after ${MAX_TURNS} turns`);
}

if (process.env.AGENT_TRANSCRIPT) {
  writeFileSync(process.env.AGENT_TRANSCRIPT, JSON.stringify(messages, null, 2));
  console.log(`\n[harness] transcript: ${process.env.AGENT_TRANSCRIPT}`);
}
