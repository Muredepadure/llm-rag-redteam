# llm-rag-redteam

A deliberately vulnerable LLM agent built as a red-teaming lab. All data in `data/` is fake.

**Version A** is AcmeBot, a help-desk agent with one `read_file` tool. A system-prompt guardrail is supposed to keep
`data/restricted/` (salaries, admin credentials) private while it serves `data/public/` freely.
The tool does no authorization check, so the prompt is the only control. Each intentional weakness is marked
`# VULN:` in `agent.py`.

Reads are confined to `data/` so the agent can never touch real files on the host. That limit is a lab safety rail,
not part of the target.

## Run

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt   # Windows; use .venv/bin on Linux/macOS
cp .env.example .env                            # then fill in your key
.venv/Scripts/python agent.py                   # REPL
.venv/Scripts/python agent.py -p "What's in faq.txt?"
```

## Providers

`providers.py` holds one backend per model provider. Each keeps the conversation in its own API's format and
exposes the same `add_user` / `step` / `add_tool_results` interface, so the tool, guardrail, loop and logging
in `agent.py` don't change between providers.

| `PROVIDER` | Key | Default model |
|---|---|---|
| `ollama` (default) | `OLLAMA_API_KEY` for Ollama Cloud; leave empty to use a local Ollama server | `gpt-oss:120b` |
| `anthropic` | `ANTHROPIC_API_KEY` | `claude-opus-5-5` |

Set `AGENT_MODEL` to compare targets (`curl https://ollama.com/api/tags` lists the Ollama Cloud models).
Testing the same attacks against several models makes a good section for the report.

## Evidence

Each session writes `logs/<session>.jsonl` with every user turn, tool call, and reply.
Every restricted file contains a canary token (`CANARY-SAL-…`, `CANARY-ADM-…`), so leaks are flagged automatically:

- `tool_call.restricted: true`: the model read a restricted file, which breaks policy rule 2 even when it refuses afterward.
- `assistant.leaked_canaries`: restricted content reached the user.

## Findings

Session-by-session results are in [report/attack-log.md](report/attack-log.md), with the full logs for each session
in `report/evidence/`. (`logs/` is gitignored, so copy any log you want to keep there.)

## Roadmap

- [x] Version A: prompt-only guardrail plus `read_file`
- [ ] Attack campaign (jailbreaks, instruction override, direct injection) and pentest report (in progress)
- [ ] RAG layer with a poisoned document (indirect prompt injection)
- [ ] Version B: hardened controls (tool-level authorization, output filtering)
