# Differential harness

The extractor has to agree with the database about what a statement is. When it
does not, the policy gate sees fewer tables than the server will read — and the
statement is allowed to read them.

This harness makes that disagreement detectable by asking the server directly:

```
statement ──▶ MySQL          ──▶  which tables did it actually read?
          └─▶ collectSqlCandidates ──▶  which tables did it name?
                                        └─▶ server's set must be a subset
```

The server is the oracle. Nothing here depends on a list of "known bad" strings,
so forms nobody wrote down are covered as soon as the server accepts them.

## Why the database and not a payload list

Obfuscation boundaries are defined by the server, not by intuition: `/*! … */` is
executed only above a version gate, `--` starts a comment only when followed by
whitespace, `#` runs to end of line, `(SELECT …)` is a legal statement. Lists
such as libinjection or the sqlmap tamper set are catalogues of *injection
shapes* — useful as a source of forms, not as a pass/fail standard, because they
answer a different question ("does this look like an attack?") than the one that
matters here ("what will this statement touch?").

The tables are read from `performance_schema.table_io_waits_summary_by_table`,
sampled before and after each statement. That sees a `UNION SELECT … FROM
other_table` that no textual heuristic would.

## Setup

Once per MySQL instance:

```bash
docker cp tests/differential/setup.sql <container>:/tmp/setup.sql
docker exec <container> mysql -uroot -p<password> < /tmp/setup.sql
```

That creates the throwaway schema `sqlguard_probe` (two tables) and the
`sqlguard_oracle` account, which is **SELECT-only**: a payload that tries to
write fails instead of damaging anything, and that failure is itself recorded.

## Running

```bash
node tests/differential/run.mjs            # skips when no oracle is reachable
SQLGUARD_ORACLE=1 node tests/differential/run.mjs   # unreachable oracle is a failure
SQLGUARD_SELFCHECK=1 node tests/differential/run.mjs # prove the comparator can fail
```

It is opt-in on purpose: CI has no MySQL, so `npm test` stays self-contained.
Wire this into a pre-release gate instead.

Configuration comes from the environment, so no machine is hard-coded:

| Variable | Default | Meaning |
| --- | --- | --- |
| `SQLGUARD_MYSQL_CONTAINER` | `agentos-mysql` | container running `mysqld` |
| `SQLGUARD_MYSQL_USER` | `sqlguard_oracle` | SELECT-only account |
| `SQLGUARD_MYSQL_PASSWORD` | `Oracle@12345` | its password |
| `SQLGUARD_MYSQL_DB` | `sqlguard_probe` | sandbox schema |
| `SQLGUARD_TIMEOUT_MS` | `15000` | per-statement timeout |

Each statement costs two round trips (execute, then sample counters), so a run is
seconds per case rather than milliseconds. That is the price of using the real
parser as the standard.

## Corpus

`corpus/mysql-native.txt` — one statement per line. `#` starts a comment line,
and a literal `\n` becomes a newline so line comments fit on one line.

`corpus/fragments.txt` — payloads, not statements. Each is embedded as a
*safely quoted* string value and must produce only `allowed_table`. Reporting
`forbidden_table` from inside a literal is a false positive: it would refuse a
statement that touches nothing it should not, which is its own failure.

`known-failures.txt` — statements currently known to be mishandled, one per line.
They report as `XFAIL` instead of `FAIL`, so the suite stays green while the debt
stays visible. If one starts passing it reports `XPASS` — remove the line then.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `PASS` | every table the server read was named |
| `FAIL` | the server read a table the extractor did not name, or the statement was not recognised at all |
| `SKIP` | the server rejected the statement, so it could not have leaked anything |
| `XFAIL` | a known defect, listed in `known-failures.txt` |
| `XPASS` | a known defect that no longer reproduces — drop it from the list |

Over-reporting (naming a table the server did not read) is a `PASS` with a note:
it fails closed, so it is noisy rather than dangerous.

## What this does not cover

Only **recognition and extraction**. Whether a policy is *configured* correctly
is a different question, covered by `report-vectors`, `subquery-vectors`, and
`qualification-vectors`. A wrong rule in the whitelist will not show up here.

## Adding cases

Add a line to a corpus file and run. If it fails and the defect is real but not
being fixed now, add the same line to `known-failures.txt` so the gap is recorded
rather than forgotten.

Prefer statements the server actually accepts — a `SKIP` proves nothing. When in
doubt, run the statement against the sandbox first and see whether it executes.
