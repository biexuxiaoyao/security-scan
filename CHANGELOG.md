# Changelog

## 0.1.0 (2026-06-07)

### ✨ Features

- **Config KV Scanner** — structured key-value analysis for config files
  (`config_file_secrets` block in `.security-scan.yml`). Supports key
  name pattern matching, key whitelist, encrypted prefix detection,
  and placeholder value validation.
- **YAML-aware key parsing** — uses `yaml.compose()` to build full
  dot-separated key paths (`spring.datasource.password`) with
  accurate line numbers.
- **Max file size limit** — files larger than 20 MiB are skipped
  (prevent OOM on huge log files). Configurable via `read_file_safe()`
  `max_size` parameter.

### 🔧 Improvements

- **AI provider rewritten** — removed `openai` SDK dependency. Uses
  stdlib `urllib` for direct HTTP calls, works with any OpenAI-compatible
  API (OpenAI, Azure, DeepSeek, Ollama, vLLM).
- **Unified encrypted prefix detection** — extracted `check_encrypted_prefix()`
  and `extract_value_from_content()` into shared `utils/encryption.py`.
  All three scanners (AST, regex, config KV) now use the same functions.
- **Shared file I/O** — CLI reads each file once and passes content
  to both regex and KV scanners, eliminating duplicate reads.
- **Rule scope cache** — `get_rules_for_scope()` results are cached
  per scope to avoid repeated filtering on every line.
- **Whitelist exact path matching** — `_path_matches()` uses prefix
  with path component boundaries (`src/test` no longer matches
  `src/test-utils/`). Glob patterns use `fnmatch`.
- **Windows GBK safety** — stdout/stderr reconfigured with
  `errors='replace'`; all git subprocess calls use explicit utf-8
  encoding.

### 🐛 Bug Fixes

- **Dead code removed**: deleted unused `hook/template.py`, removed
  unreferenced `_PORT_RANGE` regex in `context_analyzer.py`.

### 🧪 Testing

- **AI module coverage**: `classifier.py` 0% → 100%, `provider.py`
  47% → 100%, `batch_processor.py` 59% → 100% (43 tests with HTTP
  mocks simulating DeepSeek v4 Flash API).
- Overall test count: 142 → 252, overall coverage: 78% → 84%.

### 📚 Documentation

- `README.md`: updated test count, project structure (new modules).
- `docs/01-requirements/config-spec.md`: documented `config_file_secrets`
  configuration block, updated AI section for no-SDK provider setup.
