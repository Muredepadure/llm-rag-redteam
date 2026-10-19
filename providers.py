"""
Model backends. Each one owns the conversation in its provider's native
message format and exposes the same small interface to the agent loop:

    backend.add_user(text)
    turn = backend.step()             # one model call
    backend.add_tool_results(results) # [(ToolCall, output, is_error), ...]

Pick one with PROVIDER=ollama|anthropic in .env.
"""

import os
from dataclasses import dataclass, field


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict


@dataclass
class Turn:
    text: str
    tool_calls: list[ToolCall]
    stop: str  # "end" | "tool_use" | "refusal" | "max_tokens"
    usage: dict = field(default_factory=dict)
    thinking: str = ""  # model reasoning, when the provider returns it
    details: str = ""  # provider-specific extra info (e.g. refusal category)


# --------------------------------------------------------------------------
# Ollama (local server or Ollama Cloud)
# --------------------------------------------------------------------------


class OllamaBackend:
    default_model = "gpt-oss:120b"

    def __init__(self, model: str, system: str, tools: list[dict]) -> None:
        import ollama

        self.model = model
        self.errors = (ollama.ResponseError, ConnectionError)
        api_key = os.getenv("OLLAMA_API_KEY")
        # With a key we talk to Ollama Cloud; without one, to a local server.
        host = os.getenv("OLLAMA_HOST") or ("https://ollama.com" if api_key else None)
        self.target = host or "local Ollama (no OLLAMA_API_KEY set)"
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else None
        self.client = ollama.Client(host=host, headers=headers)
        self.tools = [
            {"type": "function", "function": {
                "name": t["name"], "description": t["description"],
                "parameters": t["input_schema"]}}
            for t in tools
        ]
        self.messages: list = [{"role": "system", "content": system}]
        self._calls = 0

    def add_user(self, text: str) -> None:
        self.messages.append({"role": "user", "content": text})

    def step(self) -> Turn:
        response = self.client.chat(model=self.model, messages=self.messages,
                                    tools=self.tools)
        msg = response.message
        self.messages.append(msg)

        calls = []
        for c in msg.tool_calls or []:
            self._calls += 1  # Ollama has no call ids; make our own for the logs
            calls.append(ToolCall(f"call_{self._calls}", c.function.name,
                                  dict(c.function.arguments)))

        stop = ("tool_use" if calls else
                "max_tokens" if response.done_reason == "length" else "end")
        return Turn(text=msg.content or "", tool_calls=calls, stop=stop,
                    thinking=msg.thinking or "",
                    usage={"input_tokens": response.prompt_eval_count,
                           "output_tokens": response.eval_count})

    def add_tool_results(self, results) -> None:
        for call, output, _is_error in results:
            self.messages.append({"role": "tool", "tool_name": call.name,
                                  "content": output})


# --------------------------------------------------------------------------
# Anthropic (Claude API)
# --------------------------------------------------------------------------


class AnthropicBackend:
    default_model = "claude-opus-5-5"

    def __init__(self, model: str, system: str, tools: list[dict]) -> None:
        import anthropic

        self.model = model
        self.errors = (anthropic.APIStatusError, anthropic.APIConnectionError)
        self.client = anthropic.Anthropic()
        self.target = "Claude API"
        self.system = system
        self.tools = [{**t, "strict": True} for t in tools]
        self.effort = os.getenv("AGENT_EFFORT", "medium")
        self.messages: list = []

    def add_user(self, text: str) -> None:
        self.messages.append({"role": "user", "content": text})

    def step(self) -> Turn:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=16000,
            system=self.system,
            tools=self.tools,
            output_config={"effort": self.effort},
            messages=self.messages,
        )
        # Keep full content (thinking + tool_use blocks) so the history
        # stays append-only and valid for the next request.
        self.messages.append({"role": "assistant", "content": response.content})

        stop = {"tool_use": "tool_use", "refusal": "refusal",
                "max_tokens": "max_tokens"}.get(response.stop_reason, "end")
        return Turn(
            text="".join(b.text for b in response.content if b.type == "text"),
            tool_calls=[ToolCall(b.id, b.name, b.input)
                        for b in response.content if b.type == "tool_use"],
            stop=stop,
            usage=response.usage.model_dump(),
            details=str(response.stop_details) if stop == "refusal" else "",
        )

    def add_tool_results(self, results) -> None:
        self.messages.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": call.id,
             "content": output, "is_error": is_error}
            for call, output, is_error in results
        ]})


BACKENDS = {"ollama": OllamaBackend, "anthropic": AnthropicBackend}


def make_backend(system: str, tools: list[dict]):
    provider = os.getenv("PROVIDER", "ollama").lower()
    if provider not in BACKENDS:
        raise SystemExit(f"Unknown PROVIDER={provider!r}; use one of {list(BACKENDS)}")
    cls = BACKENDS[provider]
    model = os.getenv("AGENT_MODEL") or cls.default_model
    return provider, cls(model, system, tools)
