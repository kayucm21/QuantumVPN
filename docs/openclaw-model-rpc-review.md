# Pinned OpenClaw Gateway model verifier

This is source-level evidence for OpenClaw **2026.9.9**, read from the installed
package on the owned VDS. It is not evidence of a successful inference or current
service health. Research used only package/dist source reads and Ollama metadata
GETs; no config/token reads, model load, inference or service actions.

The installed source root is
`/opt/quantum-automation/releases/q4-20261010/openclaw/node_modules/openclaw/dist/`.
The source-only artifacts are under `artifacts/quantum4-automation-review/`.

| Source | SHA-256 | Verified contract |
| --- | --- | --- |
| `call-DmvqNvMY.mjs` | `2e3b564bd0e3bef6c553ea1ac8def0bec46d86275e5fd4e91b6d0cfc3572f121` | Lines98–109: CLI mode/name + shared token + loopback omits device identity; no device store is needed. |
| `client-B4O1WKhF.mjs` | `5434ab96d41c82f8717e0bb5b1046f06d41cac0b3da9a5cbf384e0aaad8cf5cc` | Lines332–337: request envelope `type/id/method/params`; 361–367: accepted does not settle an expect-final request; 706–723: require nonempty connect challenge; 1252–1312: operator protocol4 connect fields. |
| `client-info-S_xwnr2o.mjs` | `3fcaf44fb6c276a1f16e73056810d9e0a58a228a8ce915b0dd081758dbe09cb9` | Lines16,33: CLI id and mode are both `cli`. |
| `sessions-Bw59kgfQ.mjs` | `044fb9b42bd88b3d6b326b527ff61dc029c47517fcdbd7e75629a98ec4730734` | Lines1796–1854: connect schema; 1856–1917: hello includes protocol, server version, auth method/role/scopes and supported methods. |
| `src-D2gvuSyP.mjs` | `8f5ed8aa897a9d6a23dcfb597a071d875650a96d6346c63da291308999eaea53` | Lines2932–2991: agent message/sessionKey/thinking/deliver/timeout/idempotencyKey; 3019–3022: agent.wait accepts runId and optional timeoutMs. |
| `method-scopes-C-MKLkWf.mjs` | `82c26c6c1453e07cf6637906e7278be570772f16db21863816d9f144e43b4f40` | Line94: ordinary agent messages require operator.write; session reset requires admin. Verifier supplies no model/provider override and no reset command. |
| `agent-XuZuntjH.mjs` | `373c128c874b1f12d9c24d1dba838d2d26a6f71b76bbf27f817ae1bbafef7820` | Agent handler validates params and dispatches the Gateway turn service. |
| `agent-turn-service-W_0N3NA0.mjs` | `c373460e63699a72a7b09d10a4ff02711fc36ac66568f91d9efb329101b4839d` | Lines2544–2552: accepted run identity; 2969–3007: final envelope contains runId, classified status, summary and actual result (meta.error/aborted/timeout produce failure); 3063–3070: emits that final payload on the same response path. Lines4428–4490: agent.wait reports lifecycle/terminal reply, not actual provider/model metadata; it cannot substitute for inference proof. |
| `ws-connection-CsJ9cE0L.mjs` | `b51e1190bd1ca47b2497311e798ee95c2d7acd1e1a410bc6f6c1b1aeb5862f53` | Lines323–332: Gateway sends connect.challenge with nonce before connect. |
| `embedded-agent-gxn-c3nS.mjs` | `5241e89998d2798f0621418c04438adb07b798a0b92537e91718bf116246d808` | Lines6710–6731: actual agentMeta provider/model come from reportedModelRef, not requested display text. Lines6736–6749: terminalReceipt binds runId and effective provider/model and records successfulToolNames. |

Ollama read-only metadata identified `qwen3:0.6b`, digest
`7df6b6e09427a769808717c0a93cadc4ae99ed4eb8bf5ca557c90846becea435`,
disk size522653767 bytes, GGUF Q4_K_M. `/api/ps` was empty in that sample. Disk
size is not a RAM estimate. Historical Ollama service peak1382 MiB is recorded
in `quantum4-automation-stack.md`; the separately reviewed allowance rounds this
up to1408 MiB. It is an observed historical allowance, not a guaranteed bound on
future allocations.

`tools/verify-openclaw-model-vds.py` defaults to read-only preflight. It requires
the exact pinned completed schema2 OpenClaw-only conversion, root-private
manifest/journal/access/intent, the exact service/config policy including
`tools.deny=["*"]`, correct isolated service UID, loopback readiness, exact RPC
source hashes, exact model digest, 1024 MiB/CPU25%/zero-swap service properties,
and no unit drop-ins. It refuses incomplete conversion or any drift.

The only inference opt-in is `--model-smoke`, subject to root review before its
first live invocation. It repeats preflight, drops the RPC client to UID985,
limits client address space to128 MiB/core dumps disabled/CPU60s/wall150s, and
authenticates directly to127.0.0.1:18789 using an in-memory token. It requires
token-authenticated operator.write protocol4 hello, correlates accepted/final
run identity and terminalReceipt/effective model identity with no successful
tools, and reports only proof facts, not token, prompt or response text.
No OpenClaw CLI or embedded fallback is invoked. Normal Gateway session
persistence is an expected inference side effect; the tool does not modify
configs, manifests, service units, model files or service state.

Immediately before the agent request it samples actual Ollama MemoryPeak and
MemAvailable. Peak above1408 MiB (or unavailable) blocks; MemAvailable below
`1408+384+128=1920 MiB` blocks. The allowance is never automatically increased.
Successful HTTP readiness, preflight, authenticated hello or accepted status
must not be described as model success. Only a correlated final successful
agent result with nonempty non-error/non-reasoning response and actual Ollama/Qwen metadata
can produce `ModelVerified`.
