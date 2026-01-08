# Code Indexing Tools

These tools are symlinked from `shared-rules/scripts/code-indexing/`.

## Quick Start

```bash
# Generate code index
go run ./scripts/code-indexing/indexgen docs/indexes/code-index.json .

# Search index
go run ./scripts/code-indexing/indexsearch docs/indexes/code-index.json <query>

# Extract chunks for LLM
go run ./scripts/code-indexing/extract-chunks docs/indexes/code-index.json output.json --format llm

# Find index by version
go run ./scripts/code-indexing/find-version docs/indexes --commit <commit>
```

## Documentation

See `shared-rules/docs/code-indexing/` for full documentation:
- `SCRIPTS_README.md` - Script usage guide
- `INDEX_VERSIONING.md` - Versioning strategy
- `LLM_CONTEXT_STRATEGY.md` - LLM context generation strategy

## Updating Tools

To update to latest version:
```bash
git submodule update --init --remote shared-rules
```
