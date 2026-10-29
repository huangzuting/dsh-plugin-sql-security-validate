# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-rc.2] - 2026-10-29

Fixes two bypasses reported in review, plus a third found while verifying them.

### Security

- Fixed `SELECT *` reading a column the blacklist forbids. The extractor dropped
  `*` rather than treating it as "every column", so the forbidden column was
  never in the compared set and the statement was allowed. A projection of `*`
  is now refused when a column rule governs one of the tables it covers, naming
  the expansion as `<table>.*` in the refusal. `COUNT(*)` is unaffected: it is
  an aggregate over a star argument and reveals no column value.

- Fixed a leading SQL comment skipping the check entirely. Candidate detection
  anchored on the first word of the argument, so `/* note */ SELECT …` and
  `-- note⏎SELECT …` were never recognised as SQL and therefore never judged.
  Leading `--`, `#` and `/* */` are now stripped before the keyword test and
  before parsing. Comments inside a statement were already handled by the
  parser and are unchanged.

- Fixed an unterminated block comment being treated as a statement prefix: text
  after it is still commented, so nothing after it is judged, and it is no
  longer mistaken for SQL.

- Fixed MySQL **executable comments** escaping judgment. `/*! … */` and
  `/*!50000 … */` are run by the server, but were stripped as ordinary
  comments, so the statement vanished from the extractor's view while MySQL
  executed it — including the form where the comment supplies the keyword
  itself (`/*!50000SELECT*/ …`). Their bodies are now expanded before parsing,
  quote-aware so a marker inside a string literal is left alone.

- Fixed a **parenthesised statement** being skipped. `(SELECT …)` is valid MySQL
  and failed the keyword test, so it was never judged.

- Fixed **leading empty statements** being skipped: `;SELECT …` runs on the
  server and was ignored by the extractor.

### Fixed

- Aliases are now resolved back to their tables, so `SELECT u.* FROM user u` is
  attributed to `user` instead of the alias.

### Added

- `tests/review-9968.mjs` (19 assertions) covering both reported bypasses,
  their comment variants, and the non-regressions: `COUNT(*)`, explicit safe
  column lists, and `*` on tables no column rule governs.

- `tests/obfuscation-vectors.mjs` (17 assertions) covering forms where MySQL and
  the extractor could disagree: executable comments, parenthesised statements,
  leading semicolons, BOM and exotic whitespace, comments between keywords,
  optimizer hints, and a quoted comment marker. Each case was checked against a
  real MySQL 8.0.46 server before being written as an expectation.

- `tests/differential/` — a harness that treats the database as the oracle. It
  asks `performance_schema` which tables a statement actually read and requires
  the extractor to name at least those, so an obfuscation the server accepts is
  caught whether or not anyone thought to write it down. Opt-in (`npm run
  test:differential`), because CI has no MySQL; see its README for setup.

## [1.0.0-rc.1] - 2026-10-27

Release candidate. The behaviour is what 1.0.0 is intended to ship; this tag
exists so the plugin can be installed from npm before the API and the
configuration surface are frozen.

Scope of the candidate:

- Interception of agent-generated SQL through both engines (event waterfall and
  optional monotonic guard).
- Blacklist and whitelist modes, with whitelist working fully offline.
- Per-table governance of schema-discovery statements, so an agent can inspect
  the tables it may read and not the ones it may not.
- Subquery coverage across the whole AST rather than a fixed set of fields.
- Per-turn interception card and a settings panel.
- 143 assertions across six suites.

Known limitations are listed in [`SECURITY.md`](SECURITY.md#known-boundaries-not-vulnerabilities).

## [1.0.0] - 2026-10-27

First public release. The security fixes below all landed during internal
review before publication, so no previously released version is affected.

### Security

- Fixed `DESCRIBE` / `DESC` statements bypassing the permission check entirely.
  The extractor only recognised a table after `FROM` / `JOIN` / `INTO` /
  `UPDATE`, so a metadata statement named its target somewhere the extractor
  never looked and produced an empty resource set — which every policy read as
  "nothing forbidden".

- Fixed `SHOW CREATE TABLE` and `SHOW TABLE STATUS` leaking the DDL and runtime
  statistics of unauthorised tables. Same root cause as the item above.

- Fixed statements whose resources could not be extracted skipping both the
  decision and the audit record. Ordinary `SELECT … allow` was always logged;
  what went missing was the whole entry for statements the parser reduced to an
  empty resource set, leaving them neither refused nor traceable.

- Fixed `WHERE` / `HAVING` / select-list subqueries escaping the resource set,
  which allowed an authorised outer table to read any table's rows through a
  scalar subquery. Extraction now walks the entire AST instead of reading a
  fixed list of fields, so a subquery is found wherever it appears — including
  `ORDER BY`, window definitions, `CASE WHEN`, and function arguments.

- Fixed a whitelist grant of `demo.user` also authorising `mysql.user`. The
  matcher trims a leading segment so a qualified grant still admits an
  unqualified query; that trim was applied without checking whether the resource
  was itself qualified, which let one database's grant reach another's
  same-named table.

- Added `strictDatabaseQualification` to close the reverse case: a grant written
  as a bare table name (`user`) matching `mysql.user`.

### Fixed

- Fixed CTE names being treated as physical tables, which refused legitimate
  queries such as `WITH recent AS (…) … FROM recent`.

- Fixed `DESCRIBE database.table`: the vendored parser rejects the qualified
  form, so the target is now read from the statement directly instead of being
  dropped.

- Fixed prose being treated as SQL. `explain the numbers` and `show me the data`
  opened with a SQL keyword and entered the policy pipeline as candidates.

- Fixed the same call being audited twice under strict mode. Both engines run
  per call, so a single query was counted as two.

- Fixed `column_ref.table` (an alias, as in `FROM user u` → `u.id`) being
  collected as a table name, which invented tables `u` and `o`.

- Removed a duplicated `Policy.grantedBy` definition.

### Added

- `allowSchemaDiscovery` (default `true`): whether table-less discovery such as
  `SHOW TABLES` is permitted.

- `failOnParseError` (default `false`): whether a statement the parser cannot
  interpret is refused.

- `strictDatabaseQualification` (default `false`): whether a bare whitelist
  grant may reach a qualified resource.

- Replaced the hand-written tokenizer with a vendored `node-sql-parser` 5.4.0
  (Apache-2.0). The published package is 88 MB, of which ~87 MB is browser
  bundles, alternate builds, and source maps that never load at runtime; the
  vendored copy keeps only the 2.77 MB the plugin actually uses, which also makes
  the exact version auditable and the install offline-capable.

- Test suites: `tests/report-vectors.mjs` (15 assertions),
  `tests/subquery-vectors.mjs` (26), `tests/qualification-vectors.mjs` (10).

- Per-turn interception card: each turn that touched a database shows what was
  refused, with the policy entry that matched, without leaving the conversation.

- Settings panel covering the enable switch, blacklist/whitelist mode, per-mode
  policy editing, and the audit log with per-record detail.

### Known limitations

See [`SECURITY.md`](SECURITY.md#known-boundaries-not-vulnerabilities) for the
behaviours that are deliberate rather than defects.

[1.0.0-rc.2]: https://github.com/huangzuting/dsh-plugin-sql-security-validate/releases/tag/v1.0.0-rc.2
[1.0.0-rc.1]: https://github.com/huangzuting/dsh-plugin-sql-security-validate/releases/tag/v1.0.0-rc.1
[1.0.0]: https://github.com/huangzuting/dsh-plugin-sql-security-validate/releases/tag/v1.0.0
