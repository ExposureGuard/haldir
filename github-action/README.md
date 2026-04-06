# Haldir GitHub Action

Create a governed AI agent session in your CI/CD pipeline. Every automated workflow creates a scoped session before running agent tools — enforcing permissions, spend limits, and a full audit trail.

## Why

AI agents in CI/CD need guardrails. Without governance, an agent with API keys can:

- Call any tool with no permission boundary
- Spend unlimited budget on paid APIs
- Leave no audit trail of what it did

Haldir fixes this. One step at the top of your workflow creates a session with explicit scopes, a spend cap, and immutable logging.

## Quick Start

```yaml
name: Agent Pipeline
on: push

jobs:
  governed-agent:
    runs-on: ubuntu-latest
    steps:
      - name: Create Haldir Session
        id: haldir
        uses: ExposureGuard/haldir-action@v1
        with:
          haldir_api_key: ${{ secrets.HALDIR_API_KEY }}
          agent_id: ci-pipeline
          scopes: read,execute
          spend_limit: 10

      - name: Run governed tool call
        run: |
          curl -s -X POST https://haldir.xyz/v1/proxy/call \
            -H "Authorization: Bearer ${{ secrets.HALDIR_API_KEY }}" \
            -H "Content-Type: application/json" \
            -d '{
              "tool": "scan_domain",
              "session_id": "${{ steps.haldir.outputs.session_id }}",
              "arguments": {"domain": "example.com"}
            }'

      - name: Check session spend
        run: |
          curl -s https://haldir.xyz/v1/spend?session_id=${{ steps.haldir.outputs.session_id }} \
            -H "Authorization: Bearer ${{ secrets.HALDIR_API_KEY }}"
```

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `haldir_api_key` | Yes | - | Your Haldir API key (`hld_xxx`). Store as a GitHub secret. |
| `agent_id` | No | `ci-pipeline` | Unique identifier for this agent/pipeline. |
| `scopes` | No | `read,execute` | Comma-separated permission scopes. |
| `spend_limit` | No | *(none)* | Maximum USD spend for the session. |
| `ttl` | No | `3600` | Session time-to-live in seconds. |
| `base_url` | No | `https://haldir.xyz` | Haldir API base URL (for self-hosted). |

### Available Scopes

| Scope | Description |
|---|---|
| `read` | Read data, query tools, fetch results |
| `write` | Create or modify resources |
| `execute` | Run tools via the proxy |
| `browse` | Web browsing tools |
| `spend:N` | Authorize payments up to $N |
| `admin` | Manage secrets, policies, keys |

## Outputs

| Output | Description |
|---|---|
| `session_id` | The governed session ID. Pass to all subsequent Haldir API calls. |
| `scopes` | JSON array of granted scopes. |
| `expires_at` | ISO timestamp when the session expires. |

## Examples

### Domain Security Scan on Every PR

```yaml
name: Security Audit
on: pull_request

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Create Haldir Session
        id: haldir
        uses: ExposureGuard/haldir-action@v1
        with:
          haldir_api_key: ${{ secrets.HALDIR_API_KEY }}
          agent_id: security-scanner
          scopes: read,execute
          spend_limit: 5

      - name: Scan production domain
        run: |
          RESULT=$(curl -s -X POST https://haldir.xyz/v1/proxy/call \
            -H "Authorization: Bearer ${{ secrets.HALDIR_API_KEY }}" \
            -H "Content-Type: application/json" \
            -d '{
              "tool": "scan_domain",
              "session_id": "${{ steps.haldir.outputs.session_id }}",
              "arguments": {"domain": "${{ vars.PRODUCTION_DOMAIN }}"}
            }')
          
          GRADE=$(echo "$RESULT" | jq -r '.result.grade // "unknown"')
          echo "## Domain Security Grade: $GRADE" >> $GITHUB_STEP_SUMMARY
          
          if [ "$GRADE" = "F" ]; then
            echo "::error::Production domain scored F — blocking deploy"
            exit 1
          fi
```

### Multi-Agent Pipeline with Spend Control

```yaml
name: Agent Workflow
on: workflow_dispatch

jobs:
  pipeline:
    runs-on: ubuntu-latest
    steps:
      - name: Create research session (read-only, $2 budget)
        id: researcher
        uses: ExposureGuard/haldir-action@v1
        with:
          haldir_api_key: ${{ secrets.HALDIR_API_KEY }}
          agent_id: researcher
          scopes: read,browse
          spend_limit: 2

      - name: Create executor session (can run tools, $10 budget)
        id: executor
        uses: ExposureGuard/haldir-action@v1
        with:
          haldir_api_key: ${{ secrets.HALDIR_API_KEY }}
          agent_id: executor
          scopes: read,execute,spend:10
          spend_limit: 10

      - name: Research phase
        run: |
          curl -s -X POST https://haldir.xyz/v1/proxy/call \
            -H "Authorization: Bearer ${{ secrets.HALDIR_API_KEY }}" \
            -H "Content-Type: application/json" \
            -d '{
              "tool": "web_search",
              "session_id": "${{ steps.researcher.outputs.session_id }}",
              "arguments": {"query": "latest CVEs for nginx"}
            }'

      - name: Execute phase
        run: |
          curl -s -X POST https://haldir.xyz/v1/proxy/call \
            -H "Authorization: Bearer ${{ secrets.HALDIR_API_KEY }}" \
            -H "Content-Type: application/json" \
            -d '{
              "tool": "scan_domain",
              "session_id": "${{ steps.executor.outputs.session_id }}",
              "arguments": {"domain": "example.com"}
            }'

      - name: Audit trail
        run: |
          echo "## Audit Log" >> $GITHUB_STEP_SUMMARY
          curl -s "https://haldir.xyz/v1/audit?agent_id=researcher&limit=10" \
            -H "Authorization: Bearer ${{ secrets.HALDIR_API_KEY }}" | jq '.' >> $GITHUB_STEP_SUMMARY
```

### Self-Hosted Haldir

```yaml
- name: Create session on self-hosted Haldir
  id: haldir
  uses: ExposureGuard/haldir-action@v1
  with:
    haldir_api_key: ${{ secrets.HALDIR_API_KEY }}
    agent_id: internal-agent
    scopes: read,write,execute
    base_url: https://haldir.internal.company.com
```

## How It Works

1. The action calls `POST /v1/sessions` on the Haldir API
2. Haldir creates a session with the specified scopes and spend limit
3. The session ID is exported as a GitHub Actions output
4. Subsequent steps use the session ID for governed tool calls via `/v1/proxy/call`
5. Every tool call is logged to the immutable audit trail
6. If spend exceeds the limit, further calls are denied

## Security

- **API key**: Always store `HALDIR_API_KEY` as a [GitHub encrypted secret](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions). Never hardcode it.
- **Session ID masking**: The action automatically masks the session ID in workflow logs.
- **Least privilege**: Grant only the scopes your pipeline actually needs. `read,execute` covers most CI/CD use cases.
- **Spend caps**: Always set a `spend_limit` for automated pipelines to prevent runaway costs.

## License

GPL-3.0 -- see [LICENSE](../LICENSE) in the main Haldir repository.
