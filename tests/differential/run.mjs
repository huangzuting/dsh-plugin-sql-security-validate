/**
 * Differential harness: the server is the oracle, the extractor must keep up.
 *
 * For each statement the harness asks two independent questions:
 *
 *   1. What did MySQL actually read? (`performance_schema` counter diff)
 *   2. What did the extractor say it reads? (`collectSqlCandidates`)
 *
 * A statement the server executes but the extractor does not see — or sees
 * incompletely — is a bypass, because the policy gate would wave it through.
 *
 * This is deliberately NOT the same as matching known-bad strings. The corpus is
 * a starting point, not a definition: anything the server accepts is in scope,
 * including forms nobody thought to write down.
 *
 * Opt-in. CI has no MySQL, so the suite skips unless an oracle is reachable:
 *
 *   node tests/differential/run.mjs            # skips when the oracle is absent
 *   SQLGUARD_ORACLE=1 node tests/differential/run.mjs
 */
import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { collectSqlCandidates } from '../../src/sql-parse.js'
import { checkOracle, configFromEnv, execute, readCounters } from './oracle.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))

/**
 * Fragments are embedded as a *safely quoted* string value.
 *
 * That is the point: the payload is inert data here, so the extractor must
 * report only `allowed_table`. Reporting `forbidden_table` would mean it read
 * the string contents as SQL and refused a harmlessly literal statement — a
 * false positive, which is its own kind of failure because it blocks queries
 * that touch nothing they should not.
 *
 * @param fragment the payload
 * @returns a statement whose literal value is exactly that payload
 */
function fragmentStatement(fragment) {
  const escaped = fragment.replace(/\\/g, '\\\\').replace(/'/g, "\\'")
  return `SELECT * FROM allowed_table WHERE note = '${escaped}'`
}

/**
 * Read a corpus file into entries.
 *
 * Blank lines and lines starting with `#` are skipped; a literal `\n` becomes a
 * newline so a line comment can be written on one line.
 *
 * @param name file name under corpus/
 * @returns the entries in file order
 */
function loadCorpus(name) {
  const path = join(HERE, 'corpus', name)
  if (!existsSync(path)) return []
  return readFileSync(path, 'utf8')
    .split('\n')
    .map(line => line.replace(/\\n/g, '\n'))
    .filter(line => line.trim() !== '' && !line.trimStart().startsWith('#'))
    .map(line => line.trimEnd())
}

/** Known-bad statements, so a real defect is recorded rather than silently red. */
function loadKnownFailures() {
  const path = join(HERE, 'known-failures.txt')
  if (!existsSync(path)) return new Set()
  return new Set(
    readFileSync(path, 'utf8')
      .split('\n')
      .map(line => line.replace(/\\n/g, '\n'))
      .filter(line => line.trim() !== '' && !line.trimStart().startsWith('#'))
      .map(line => line.trimEnd()),
  )
}

/**
 * Ask the extractor what a statement reads.
 * @param statement the SQL
 * @returns whether it was recognised and which tables it named
 */
function analyse(statement) {
  const candidates = collectSqlCandidates({ sql: statement }, { keys: ['sql'] })
  if (candidates.length === 0) return { recognized: false, tables: [] }
  return { recognized: true, tables: candidates[0].parsed.tables }
}

/** The bare table name, so `db.table` and `table` compare equal. */
function leafName(name) {
  const lower = name.toLowerCase()
  return lower.slice(lower.lastIndexOf('.') + 1)
}

/**
 * Compare what the server read against what the extractor named.
 *
 * Kept separate from the loop so it can be exercised without a database: a
 * harness that cannot fail is worse than no harness, and `SQLGUARD_SELFCHECK=1`
 * proves this one rejects both failure modes.
 *
 * @param readTables tables the server actually read
 * @param namedTables tables the extractor reported
 * @param recognized whether the extractor recognised the statement at all
 * @returns the verdict and a human-readable detail
 */
function compareTables(readTables, namedTables, recognized) {
  if (!recognized) {
    return { verdict: 'FAIL', detail: `server read ${JSON.stringify(readTables)} but the extractor did not recognise the statement` }
  }
  const missed = readTables.filter(table => !namedTables.includes(table))
  if (missed.length > 0) {
    return { verdict: 'FAIL', detail: `server read ${JSON.stringify(missed)}, extractor named ${JSON.stringify(namedTables)}` }
  }
  const extra = namedTables.filter(table => !readTables.includes(table))
  return {
    verdict: 'PASS',
    detail: extra.length > 0 ? `also named ${JSON.stringify(extra)} (over-reporting fails closed)` : undefined,
  }
}

if (process.env.SQLGUARD_SELFCHECK === '1' || process.argv.includes('--selfcheck')) {
  const checks = [
    ['unrecognised statement that reads a table', compareTables(['forbidden_table'], [], false), 'FAIL'],
    ['recognised but missing a table', compareTables(['forbidden_table'], ['allowed_table'], true), 'FAIL'],
    ['complete', compareTables(['allowed_table'], ['allowed_table'], true), 'PASS'],
  ]
  let bad = 0
  for (const [label, outcome, expected] of checks) {
    const ok = outcome.verdict === expected
    if (!ok) bad += 1
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}: ${outcome.verdict} (expected ${expected})`)
  }
  console.log(bad === 0 ? '\nself-check: the comparator rejects both failure modes' : '\nself-check: comparator is broken')
  process.exit(bad === 0 ? 0 : 1)
}

const config = configFromEnv()
const problem = checkOracle(config)
if (problem !== undefined && process.env.SQLGUARD_ORACLE !== '1') {
  console.log(`differential: skipped — ${problem}`)
  console.log('  set SQLGUARD_ORACLE=1 to treat an unreachable oracle as a failure')
  process.exit(0)
}
if (problem !== undefined) {
  console.error(`differential: ${problem}`)
  console.error('  run tests/differential/setup.sql against the oracle first')
  process.exit(1)
}

const knownFailures = loadKnownFailures()
const statements = loadCorpus('mysql-native.txt')
const fragments = loadCorpus('fragments.txt')

const results = []
let counters = readCounters(config)

// ── statement corpus: every table the server read must be named ────────────
for (const statement of statements) {
  const outcome = execute(config, statement, counters)
  counters = outcome.counters
  const extractor = analyse(statement)
  const readTables = outcome.tablesRead.map(leafName)
  const namedTables = extractor.tables.map(leafName)

  let verdict
  let detail
  if (!outcome.ok) {
    // The server refused it, so there is nothing it could have leaked.
    verdict = 'SKIP'
    detail = `server rejected it (${outcome.errorText ?? 'error'})`
  } else {
    const comparison = compareTables(readTables, namedTables, extractor.recognized)
    verdict = comparison.verdict
    detail = comparison.detail
  }

  const isKnown = knownFailures.has(statement)
  if (verdict === 'FAIL' && isKnown) verdict = 'XFAIL'
  if (verdict === 'PASS' && isKnown) verdict = 'XPASS'

  results.push({ kind: 'statement', statement, verdict, detail, readTables, namedTables })
}

// ── fragment corpus: a payload in a string literal must not invent a table ──
for (const fragment of fragments) {
  const statement = fragmentStatement(fragment)
  const outcome = execute(config, statement, counters)
  counters = outcome.counters
  const extractor = analyse(statement)
  const namedTables = extractor.tables.map(leafName)

  let verdict
  let detail
  if (!outcome.ok) {
    verdict = 'SKIP'
    detail = `server rejected the template (${outcome.errorText ?? 'error'})`
  } else if (!namedTables.includes('allowed_table')) {
    verdict = 'FAIL'
    detail = `template reads allowed_table but the extractor named ${JSON.stringify(namedTables)}`
  } else if (namedTables.includes('forbidden_table')) {
    verdict = 'FAIL'
    detail = 'reported forbidden_table from a string literal (false positive)'
  } else {
    verdict = 'PASS'
  }

  if (verdict === 'FAIL' && knownFailures.has(fragment)) verdict = 'XFAIL'
  results.push({ kind: 'fragment', statement: fragment, verdict, detail, namedTables })
}

// ── report ─────────────────────────────────────────────────────────────────
const groups = ['FAIL', 'XPASS', 'XFAIL', 'SKIP', 'PASS']
const counts = Object.fromEntries(groups.map(group => [group, 0]))
for (const result of results) counts[result.verdict] += 1

for (const group of ['FAIL', 'XPASS', 'XFAIL', 'SKIP']) {
  const rows = results.filter(result => result.verdict === group)
  if (rows.length === 0) continue
  console.log(`\n=== ${group} (${rows.length}) ===`)
  for (const row of rows) {
    console.log(`  ${row.kind === 'fragment' ? '[frag]' : '[stmt]'} ${JSON.stringify(row.statement)}`)
    if (row.detail !== undefined) console.log(`         ${row.detail}`)
  }
}

console.log('\n=== summary ===')
console.log(`  corpus:     ${statements.length} statements, ${fragments.length} fragments`)
for (const group of ['PASS', 'XFAIL', 'XPASS', 'SKIP', 'FAIL']) {
  console.log(`  ${group.padEnd(7)} ${counts[group]}`)
}

const failed = counts.FAIL
console.log(failed === 0
  ? '\ndifferential: no bypass found in this corpus'
  : `\ndifferential: ${failed} statement(s) bypassed the extractor`)
process.exit(failed === 0 ? 0 : 1)
