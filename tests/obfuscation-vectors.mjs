// Obfuscation vectors: forms where MySQL and the extractor could disagree about
// what a statement is. Every case here was checked against a real MySQL 8.0.46
// server first — the ones marked "MySQL executes" were confirmed to run, so
// failing to recognise them would be a live bypass rather than a theoretical one.
import assert from 'node:assert/strict'
import { parseSql, collectSqlCandidates } from '../src/sql-parse.js'
import { Policy, mergePolicy } from '../src/policy.js'

/** `db.admin` forbidden, and two columns of `db.user`. */
const blacklist = () => new Policy({
  securityMode: 'blacklist',
  ...mergePolicy({ tables: ['db.admin'], columns: ['db.user.phone', 'db.user.idcard'] }, undefined),
})

function decide(sql) {
  const candidates = collectSqlCandidates({ sql }, { keys: ['sql'] })
  if (candidates.length === 0) return { verdict: 'NO-CANDIDATE', tables: [], columns: [] }
  const parsed = candidates[0].parsed
  const outcome = blacklist().decide(parsed)
  return { verdict: outcome.allowed ? 'ALLOW' : 'DENY', tables: parsed.tables, columns: outcome.forbiddenColumns }
}

const cases = []
const check = (label, fn) => cases.push({ label, fn })

// ── MySQL executable comments (verified: the server runs the body) ─────────
const EXECUTABLE = [
  ['versioned', '/*!50000 SELECT * FROM db.admin */'],
  ['no space after !', '/*!50000SELECT * FROM db.admin*/'],
  ['comment supplies the keyword', '/*!50000SELECT*/ * FROM db.admin'],
  ['bare', '/*! SELECT * FROM db.admin */'],
  ['mid-statement', 'SELECT /*!50000 * */ FROM db.admin'],
]

for (const [label, sql] of EXECUTABLE) {
  check(`executable comment (${label}) is judged, not skipped`, () => {
    assert.equal(decide(sql).verdict, 'DENY')
    assert.ok(decide(sql).tables.includes('db.admin'), 'the table inside the comment must be extracted')
  })
}

check('a quoted executable-comment marker is left alone', () => {
  // The marker sits inside a string literal, so it must not be expanded.
  const parsed = parseSql("SELECT '/*!50000 x */' AS note FROM db.product")
  assert.deepEqual(parsed.tables, ['db.product'])
  assert.equal(decide("SELECT '/*!50000 x */' AS note FROM db.product").verdict, 'ALLOW')
})

// ── parenthesised statement (verified: MySQL runs it) ─────────────────────
check('parenthesised statement is judged', () => {
  assert.equal(decide('(SELECT * FROM db.admin)').verdict, 'DENY')
  assert.equal(decide('((SELECT * FROM db.admin))').verdict, 'DENY')
  assert.equal(decide('( SELECT * FROM db.admin )').verdict, 'DENY')
})

// ── leading empty statements (verified: MySQL runs it) ────────────────────
check('leading semicolons are skipped before judging', () => {
  assert.equal(decide(';SELECT * FROM db.admin').verdict, 'DENY')
  assert.equal(decide(';;SELECT * FROM db.admin').verdict, 'DENY')
  assert.equal(decide('; ; SELECT * FROM db.admin').verdict, 'DENY')
})

check('a later statement in the same string is judged too', () => {
  assert.equal(decide('SELECT 1; SELECT * FROM db.admin').verdict, 'DENY')
})

// ── whitespace and encoding noise ─────────────────────────────────────────
check('BOM and exotic whitespace do not hide the keyword', () => {
  for (const sql of ['\uFEFFSELECT * FROM db.admin', '\v\f SELECT * FROM db.admin', '\t\r\n SELECT * FROM db.admin']) {
    assert.equal(decide(sql).verdict, 'DENY', JSON.stringify(sql))
  }
})

// ── comments in other positions ───────────────────────────────────────────
check('comments between keywords still parse', () => {
  assert.equal(decide('SELECT/**/ * FROM db.admin').verdict, 'DENY')
  assert.equal(decide('SELECT */**/FROM db.admin').verdict, 'DENY')
})

check('a double dash without whitespace is not a comment', () => {
  // MySQL treats `--x` as arithmetic, not a comment; the statement still runs.
  const parsed = parseSql('--x\nSELECT * FROM db.admin')
  assert.deepEqual(parsed.tables, ['db.admin'])
})

check('optimizer hints are not executable code', () => {
  assert.equal(decide('/*+ MAX_EXECUTION_TIME(1) */ SELECT * FROM db.admin').verdict, 'DENY')
})

// ── star still governed through every wrapper ────────────────────────────
check('star behind a comment still triggers the column rule', () => {
  assert.equal(decide('/* c */ SELECT * FROM db.user').verdict, 'DENY')
  assert.equal(decide('(SELECT * FROM db.user)').verdict, 'DENY')
  assert.equal(decide('/*!50000 SELECT * FROM db.user */').verdict, 'DENY')
})

check('schema-qualified star is attributed correctly', () => {
  const result = decide('SELECT db.user.* FROM db.user')
  assert.equal(result.verdict, 'DENY')
  // The marker names the expansion; the star's table slot carries no schema, so
  // either spelling is acceptable as long as it points at the ruled table.
  assert.equal(result.columns.length, 1)
  assert.ok(result.columns[0].endsWith('.*'), result.columns[0])
  assert.ok(result.columns[0].includes('user'), result.columns[0])
})

// ── non-regressions ──────────────────────────────────────────────────────
check('empty statements and comment-only text are not SQL', () => {
  for (const text of [';', ';;', '/* only */', '-- only', '/*! */']) {
    assert.equal(collectSqlCandidates({ sql: text }, { keys: ['sql'] }).length, 0, JSON.stringify(text))
  }
})

check('ordinary statements are unaffected', () => {
  assert.equal(decide('SELECT id FROM db.product').verdict, 'ALLOW')
  assert.equal(decide('SELECT COUNT(*) FROM db.user').verdict, 'ALLOW')
  assert.equal(decide('/* c */ SELECT id FROM db.product').verdict, 'ALLOW')
})

let passed = 0
let failed = 0
for (const { label, fn } of cases) {
  try {
    fn()
    passed += 1
  } catch (error) {
    failed += 1
    console.log(`FAIL  ${label}\n      ${String(error.message).split('\n').join('\n      ')}`)
  }
}
console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed === 0 ? 0 : 1)
