// Regression suite for the two bypasses reported on PR #9968.
//
// 1. `SELECT *` expanded to every column, so a column-level blacklist never saw
//    the forbidden column and let the statement through.
// 2. A leading SQL comment made the statement unrecognisable as SQL, so it was
//    dropped before judging — a comment was a way past every policy.
import assert from 'node:assert/strict'
import { parseSql, collectSqlCandidates } from '../src/sql-parse.js'
import { Policy, mergePolicy } from '../src/policy.js'

/** Blacklist: two columns of `db.user` are forbidden, `db.product` is clean. */
const blacklist = () => new Policy({
  securityMode: 'blacklist',
  ...mergePolicy({ tables: ['db.admin'], columns: ['db.user.phone', 'db.user.idcard'] }, undefined),
})

/** Whitelist: only `demo.user` granted. */
const whitelist = () => new Policy({
  securityMode: 'whitelist_emulate',
  ...mergePolicy({ tables: [], columns: [], grantedTables: ['demo.user'] }, undefined),
})

/** Decide through the same path the interceptor uses. */
function decide(policy, sql) {
  const candidates = collectSqlCandidates({ sql }, { keys: ['sql'] })
  if (candidates.length === 0) return { verdict: 'NO-CANDIDATE', columns: [], tables: [] }
  const parsed = candidates[0].parsed
  const outcome = policy.decide(parsed)
  return {
    verdict: outcome.allowed ? 'ALLOW' : 'DENY',
    columns: outcome.forbiddenColumns,
    tables: parsed.tables,
  }
}

const cases = []
const check = (label, fn) => cases.push({ label, fn })

// ── issue 1: `*` must not read a forbidden column ─────────────────────────
check('SELECT * on a table with a forbidden column is refused', () => {
  const result = decide(blacklist(), 'SELECT * FROM db.user')
  assert.equal(result.verdict, 'DENY')
  assert.deepEqual(result.columns, ['db.user.*'], 'the refusal names the expanded column set')
})

check('qualified * is refused and traced back to its table', () => {
  assert.equal(decide(blacklist(), 'SELECT u.* FROM db.user u').verdict, 'DENY')
  assert.equal(decide(blacklist(), 'SELECT u.* FROM db.user AS u').verdict, 'DENY')
})

check('* joined with a ruled table is refused', () => {
  assert.equal(decide(blacklist(), 'SELECT * FROM db.user u JOIN db.product p ON p.id = u.id').verdict, 'DENY')
})

check('* on a table with no column rule still runs', () => {
  assert.equal(decide(blacklist(), 'SELECT * FROM db.product').verdict, 'ALLOW')
  assert.equal(decide(blacklist(), 'SELECT p.* FROM db.product p').verdict, 'ALLOW')
})

check('COUNT(*) is not a column expansion', () => {
  const parsed = parseSql('SELECT COUNT(*) FROM db.user')
  assert.equal(parsed.star, false, 'COUNT(*) reveals no column value')
  assert.equal(decide(blacklist(), 'SELECT COUNT(*) FROM db.user').verdict, 'ALLOW')
  assert.equal(decide(blacklist(), 'SELECT COUNT(*) AS n FROM db.user').verdict, 'ALLOW')
})

check('an explicit safe column list still runs', () => {
  assert.equal(decide(blacklist(), 'SELECT id, name FROM db.user').verdict, 'ALLOW')
})

check('an explicit forbidden column is still refused by name', () => {
  const result = decide(blacklist(), 'SELECT phone FROM db.user')
  assert.equal(result.verdict, 'DENY')
  assert.deepEqual(result.columns, ['phone'])
})

check('whitelist keeps * inside a granted table', () => {
  // Granting the table admits all of its columns, so `*` does not exceed the grant.
  assert.equal(decide(whitelist(), 'SELECT * FROM demo.user').verdict, 'ALLOW')
})

check('whitelist still refuses * across an ungranted table', () => {
  assert.equal(decide(whitelist(), 'SELECT * FROM demo.orders').verdict, 'DENY')
})

// ── issue 2: a leading comment must not skip the check ────────────────────
const COMMENTED = [
  ['block comment', '/* hi */ SELECT * FROM db.admin'],
  ['line comment', '-- hi\nSELECT * FROM db.admin'],
  ['hash comment', '# hi\nSELECT * FROM db.admin'],
  ['stacked comments', '   /* a */ /* b */ SELECT * FROM db.admin'],
  ['comment then whitespace', '/* a */\n\n  -- b\nSELECT * FROM db.admin'],
  ['multiline block', '/*\n multi\n line\n*/\nSELECT * FROM db.admin'],
]

for (const [label, sql] of COMMENTED) {
  check(`leading ${label} no longer skips the check`, () => {
    const candidates = collectSqlCandidates({ sql }, { keys: ['sql'] })
    assert.equal(candidates.length, 1, 'the statement must still be a candidate')
    assert.equal(decide(blacklist(), sql).verdict, 'DENY')
  })
}

check('a comment before an allowed statement still allows it', () => {
  assert.equal(decide(blacklist(), '/* note */ SELECT id FROM db.product').verdict, 'ALLOW')
})

check('prose after a comment is still not SQL', () => {
  for (const text of ['/* x */ explain the numbers', '-- x\nshow me the data']) {
    assert.equal(collectSqlCandidates({ sql: text }, { keys: ['sql'] }).length, 0, text)
  }
})

check('an unterminated block comment is not treated as a statement', () => {
  const parsed = parseSql('/* never closed SELECT * FROM db.admin')
  assert.equal(parsed.isSql, false)
})

check('a comment-only string is not a statement', () => {
  assert.equal(parseSql('-- just a note').isSql, false)
  assert.equal(parseSql('/* just a note */').isSql, false)
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
