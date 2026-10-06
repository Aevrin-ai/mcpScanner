# AI review

AI review is an optional second opinion. It is off unless you turn it on.

```bash
pip install "aevrin-mcp-scanner[ai]"
export ANTHROPIC_API_KEY=...          # or OPENAI_API_KEY, XAI_API_KEY, OPENROUTER_API_KEY, GROQ_API_KEY
mcp-scanner scan tools.json --ai-provider anthropic
```

## Providers

| Provider | SDK | API | Default model | Key |
|---|---|---|---|---|
| `openai` | `openai` | Responses API | `gpt-5.5` | `OPENAI_API_KEY` |
| `anthropic` | `anthropic` | Messages API | `claude-sonnet-5-5` | `ANTHROPIC_API_KEY` |
| `xai` | `xai_sdk` | Chat (gRPC) | `grok-4.6` | `XAI_API_KEY` |
| `openrouter` | `openai` (pointed at OpenRouter) | Chat Completions | `anthropic/claude-sonnet-5.5` | `OPENROUTER_API_KEY` |
| `groq` | `openai` (pointed at Groq) | Chat Completions | `openai/gpt-oss-120b` | `GROQ_API_KEY` |

Pick another model with `--ai-model` or `ai.model`. Install only the SDK you need, for example
`pip install "aevrin-mcp-scanner[anthropic]"`.

### OpenRouter

OpenRouter gives one key for models from many companies. Model names include the company:

```bash
pip install "aevrin-mcp-scanner[openrouter]"
export OPENROUTER_API_KEY=...
mcp-scanner scan tools.json --ai-provider openrouter                                  # anthropic/claude-sonnet-5.5
mcp-scanner scan tools.json --ai-provider openrouter --ai-model openai/gpt-5-mini     # a cheaper model
```

OpenRouter reports the real cost of every call, so the report shows a cost even without `ai.pricing`.
In our tests one review of a small server took about 2,500 input and 1,100 output tokens, around 2 US cents
with the default model.

## AI setup for repositories

The same provider can also work out how to install and start a server from a repository (`--run`), when
automatic setup cannot. It uses the same redaction and random markers as the review. See
[repositories.md](repositories.md#when-automatic-setup-is-not-enough-ai-setup). Its calls and cost are added to
the report's AI usage. Turn it off with `--ai-setup never` or `ai.setup: never`.

### Groq

Groq runs open models very fast, and has a free tier. Get a key at https://console.groq.com/keys.

```bash
pip install "aevrin-mcp-scanner[groq]"
export GROQ_API_KEY=...
mcp-scanner scan tools.json --ai-provider groq                                 # openai/gpt-oss-120b
mcp-scanner scan tools.json --ai-provider groq --ai-model openai/gpt-oss-20b   # smaller and faster
```

The default model reasons before it answers. The scanner asks for low reasoning effort and adds 1,000 tokens
of room on top of `ai.max_output_tokens`, so the reasoning cannot cut off the JSON answer. Groq does not report
prices, so set `ai.pricing` to see a cost.

The free tier allows 8,000 tokens per minute, and Groq counts the answer room you ask for, not only what the
model uses. When a request is too large, the scanner shrinks the answer room to fit and sends it once more. If
the prompt alone is too large, the error says so: lower `ai.max_input_chars` (for example to 12000). When
several calls come close together, the SDK waits and retries (`ai.max_retries`).

In our tests `openai/gpt-oss-120b` wrote good reviews, but its setup plans for `--run` were weaker than a
larger model's: it twice planned `uv pip install .` for a repository without `pyproject.toml`. Automatic setup
is the fallback, so the scan still worked. For hard repositories, a stronger model through OpenRouter, Anthropic,
or OpenAI plans better.

## What the AI can and cannot do

The AI may:

- give each finding a verdict (`likely-real`, `likely-false-positive`, `unsure`) with a short explanation,
- add "AI observations": risks no rule found, always shown as unverified,
- write a short summary for the server.

The AI may never:

- delete a finding,
- change a finding's severity, status, or risk points.

Its notes sit next to the deterministic results and are clearly labelled. The grade never depends on the AI.

## Keeping secrets and instructions out

Server text is hostile. Before anything is sent:

1. **Secrets are removed.** The same patterns that find secrets in scans replace them with
   `[REDACTED ...]`. Planted canary values are removed too.
2. **Size is limited** (`ai.max_input_chars`).
3. **The text is fenced.** It is wrapped in random markers like `<<<UNTRUSTED_DATA_3f9c...>>>`. The system
   prompt tells the model that everything inside is data to analyze, never instructions to follow. The markers
   change on every call, so a server cannot close the fence in advance.

The model answers in JSON. Anything that does not parse is reported as an AI error. AI errors never fail a scan.

## Budgets and cost

| Setting | Default | Meaning |
|---|---|---|
| `ai.max_calls` | 20 | calls per scan (one call per server) |
| `ai.max_input_chars` | 24000 | characters of server data per call |
| `ai.max_output_tokens` | 2000 | answer size |
| `ai.timeout` | 60 | seconds per call |
| `ai.max_retries` | 2 | retries on network errors |
| `ai.setup` | `auto` | AI setup for `--run` repositories: `auto`, `always`, or `never` |

Every report shows calls, failed calls, and input and output tokens. Set `ai.pricing` to see an estimated cost:

```yaml
ai:
  pricing:
    input_per_million: 3.0      # your provider's price in USD per million input tokens
    output_per_million: 15.0
```

Prices change often, so the scanner does not guess them. When `ai.pricing` is not set and the provider reports
the cost itself (OpenRouter does), that reported cost is shown instead.

## Adding a provider

Write a subclass of `AIProvider` in `src/mcp_scanner/ai/providers/` with a `complete(system, user)` method
that returns `AIResponse(text, input_tokens, output_tokens)`, and add it to `PROVIDERS`.
