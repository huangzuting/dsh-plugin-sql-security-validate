# Vendored: node-sql-parser 5.4.0

**Why vendored.** The published package is 88 MB, of which ~87 MB is artifacts
this plugin never loads: `umd/` (44.9 MB of browser bundles), `build/` (23.3 MB
of alternate builds), and `*.map` (76.2 MB of source maps). Installing it as a
normal npm dependency therefore puts 88 MB on disk for code whose runtime
footprint is 2.4 MB. A SQL permission gate is installed in environments that
care about supply-chain surface, so the parser is pinned in-tree instead:

- the exact version is auditable in this repo, not resolved at install time;
- no install-time network fetch for it;
- the plugin works offline.

**What was kept.** Only what the runtime requires:

| Path | Purpose |
| --- | --- |
| `index.js` | the parser (2.39 MB, all dialects inlined) |
| `ast/` | AST type helpers used by `index.js` |
| `lib/` | shared helpers used by `index.js` |
| `node_modules/big-integer/` | the single runtime dependency (171 KB) |
| `package.json.orig` | upstream manifest, kept for provenance |

**License.** node-sql-parser is **Apache-2.0** (see `LICENSE`). big-integer is
MIT. Both licenses travel with the vendored code, as Apache-2.0 requires.
This plugin's own license (MIT) does not relicense them.

**Not modified.** `index.js`, `ast/`, `lib/`, and `big-integer/` are byte-for-byte
copies of the published artifacts. Do not patch them in place; upgrade by
re-vendoring from a newer release and re-running `npm test`.

**Upgrading.** Install the target version in a scratch directory, copy the same
subset, update the version here and in `../package.json` (`dsh.vendor`), then run
the suite. `tests/parser-vendor.mjs` asserts the vendored copy still resolves and
parses every statement shape the policy engine relies on.
