// Regression suite built from the third-party security report.
//
// Every vector below is one the report executed against the plugin. The suite
// pins the CORRECT behaviour, which is not "refuse everything": a permission
// gate that blocks schema discovery leaves the agent unable to write any
// query, defeating the purpose of guardrailed 问数. The contract is:
//
//   - a table the caller may read  → discovery allowed;
//   - a table the caller may not   → discovery refused;
//   - a statement naming no table  → governed by `allowSchemaDiscovery`.
import assert from 'node:assert/strict'
import { parseSql, collectSqlCandidates } from '../src/sql-parse.js'
import { Policy, mergePolicy } from '../src/policy.js'

/** Whitelist fixture matching the report's configuration. */
const allowUserOnly = () => new Policy({
  securityMode: 'whitelist_emulate',
  ...mergePolicy({ tables: [], columns: [], grantedTables: ['demo.user'] }, undefined),
})

/** Blacklist fixture: the shipped defaults. */
const blacklistDefaults = () => new Policy({
  securityMode: 'blacklist',
  ...mergePolicy({ tables: ['db.admin', 'db.sensitive_log'], columns: ['db.user.phone'] }, undefined),
})

/** Decide one statement under one policy. */
function decide(policy, sql) {
  const candidates = collectSqlCandidates({ sql }, { keys: ['sql'] })
  if (candidates.length === 0) return { verdict: 'NO-CANDIDATE', parsed: undefined }
  const parsed = candidates[0].parsed
  return { verdict: policy.decide(parsed).allowed ? 'ALLOW' : 'DENY', parsed }
}

const cases = []
const check = (label, fn) => cases.push({ label, fn })

// ── VULN-01: DESCRIBE must be policed ───────────────────────────────────────
check('VULN-01 DESCRIBE an unauthorised table is refused', () => {
  for (const sql of ['DESCRIBE admin', 'DESC admin', 'DESCRIBE sensitive_log', 'DESCRIBE user_private']) {
    const { verdict, parsed } = decide(allowUserOnly(), sql)
    assert.equal(verdict, 'DENY', sql)
    assert.equal(parsed.tables.length, 1, `${sql} must name a table`)
  }
})

check('VULN-01 DESCRIBE an authorised table is allowed', () => {
  // The AI must be able to learn the shape of a table it may read.
  for (const sql of ['DESCRIBE demo.user', 'DESC demo.user']) {
    assert.equal(decide(allowUserOnly(), sql).verdict, 'ALLOW', sql)
  }
})

// ── VULN-02: SHOW family ───────────────────────────────────────────────────
check('VULN-02 SHOW CREATE TABLE an unauthorised table is refused', () => {
  for (const sql of [
    'SHOW CREATE TABLE admin',
    'SHOW COLUMNS FROM user_private',
    'SHOW INDEX FROM user_private',
  ]) {
    const { verdict } = decide(allowUserOnly(), sql)
    assert.equal(verdict, 'DENY', sql)
  }
})

check('VULN-02 SHOW … LIKE a literal table name is refused', () => {
  // The name lives in a string literal; the parser rejects this form outright,
  // so the extractor recovers it from the predicate.
  const { verdict, parsed } = decide(allowUserOnly(), "SHOW TABLE STATUS LIKE 'sensitive_log'")
  assert.equal(verdict, 'DENY')
  assert.deepEqual(parsed.tables, ['sensitive_log'], 'the literal target must be recovered')
})

check('VULN-02 SHOW CREATE TABLE an authorised table is allowed', () => {
  assert.equal(decide(allowUserOnly(), 'SHOW CREATE TABLE demo.user').verdict, 'ALLOW')
})

check('VULN-02 the old false positive is gone', () => {
  // `SHOW COLUMNS` used to be refused only because `COLUMNS` looked like an
  // unauthorised column. It must now be refused because the TABLE is refused,
  // and allowed when the table is granted.
  const granted = new Policy({
    securityMode: 'whitelist_emulate',
    ...mergePolicy({ tables: [], columns: [], grantedTables: ['demo.user_private'] }, undefined),
  })
  assert.equal(decide(granted, 'SHOW COLUMNS FROM user_private').verdict, 'ALLOW',
    'no phantom column named COLUMNS should block an authorised table')
})

// ── VULN-03: audit reachability ────────────────────────────────────────────
check('VULN-03 table-less statements still become candidates', () => {
  // They previously returned zero candidates, skipping BOTH the decision and
  // the audit record. They must reach the pipeline so they can be logged.
  for (const sql of ['SHOW TABLES', 'SHOW DATABASES', 'SHOW TABLES FROM demo']) {
    const candidates = collectSqlCandidates({ sql }, { keys: ['sql'] })
    assert.equal(candidates.length, 1, `${sql} must be a candidate`)
  }
})

check('VULN-03 a table-less statement is flagged as discovery', () => {
  const { parsed } = decide(allowUserOnly(), 'SHOW TABLES')
  assert.equal(parsed.metadata, true)
  assert.deepEqual(parsed.tables, [], 'it names no table for the policy to judge')
})

// ── the data plane the report found already correct ────────────────────────
check('identifier obfuscation is still normalised', () => {
  for (const sql of [
    'SELECT * FROM USER_PRIVATE',
    'SELECT * FROM `user_private`',
    'SELECT * FROM demo.user_private',
    'SELECT * FROM `demo`.`user_private`',
  ]) {
    assert.equal(decide(allowUserOnly(), sql).verdict, 'DENY', sql)
  }
})

check('JOIN resources are complete', () => {
  const { verdict, parsed } = decide(
    allowUserOnly(),
    'SELECT u.name, p.* FROM demo.user u JOIN demo.user_private p ON p.user_id = u.id',
  )
  assert.equal(verdict, 'DENY')
  assert.deepEqual(parsed.tables.sort(), ['demo.user', 'demo.user_private'])
})

check('system metadata tables are policed', () => {
  const { verdict } = decide(
    allowUserOnly(),
    'SELECT column_name FROM information_schema.columns WHERE table_name = \'user_private\'',
  )
  assert.equal(verdict, 'DENY')
})

check('a column reference does not bypass its table', () => {
  for (const sql of [
    'SELECT phone FROM user_private',
    'SELECT (phone) FROM user_private',
    'SELECT user_id, phone FROM user_private',
  ]) {
    assert.equal(decide(allowUserOnly(), sql).verdict, 'DENY', sql)
  }
})

check('EXPLAIN of a refused statement is refused', () => {
  const { verdict, parsed } = decide(allowUserOnly(), 'EXPLAIN SELECT * FROM admin')
  assert.equal(verdict, 'DENY')
  assert.deepEqual(parsed.tables, ['admin'], 'the inner statement supplies the table')
})

// ── blacklist mode parity ──────────────────────────────────────────────────
check('blacklist mode also covers DESCRIBE', () => {
  assert.equal(decide(blacklistDefaults(), 'DESCRIBE db.admin').verdict, 'DENY')
  assert.equal(decide(blacklistDefaults(), 'DESCRIBE db.user').verdict, 'ALLOW')
})

// ── prose must never enter the pipeline ────────────────────────────────────
check('prose that opens with a SQL keyword is not a candidate', () => {
  for (const text of ['explain the numbers', 'show me the data', 'describe this problem']) {
    assert.equal(collectSqlCandidates({ sql: text }, { keys: ['sql'] }).length, 0, text)
  }
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
