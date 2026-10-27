// Unit checks for the SQL resource extractor and the policy engine.
// Run: node tests/unit.mjs
import assert from 'node:assert/strict'
import { parseSql, collectSqlCandidates } from '../src/sql-parse.js'
import { Policy, mergePolicy, validatePolicyEnvelope, RemotePolicyClient } from '../src/policy.js'

let passed = 0
let failed = 0
function check(label, fn) {
  try {
    fn()
    passed += 1
  } catch (error) {
    failed += 1
    console.log(`FAIL  ${label}\n      ${String(error.message).split('\n').join('\n      ')}`)
  }
}

// ── parser: table extraction ────────────────────────────────────────────────
check('simple select', () => {
  const r = parseSql('SELECT id, name FROM db.user WHERE id = 1')
  assert.equal(r.isSql, true)
  assert.deepEqual(r.tables, ['db.user'])
  assert.ok(r.columns.includes('id'))
  assert.ok(r.columns.includes('name'))
  assert.ok(!r.columns.includes('1'), 'a numeric literal is not a column')
})

check('multi-table join with aliases', () => {
  const r = parseSql('SELECT u.id, o.total FROM db.user u LEFT JOIN db.orders o ON o.user_id = u.id')
  assert.deepEqual(r.tables, ['db.orders', 'db.user'])
  assert.ok(r.columns.includes('u.id'), 'alias column kept')
  assert.ok(r.columns.includes('o.total'), 'join target column kept')
})

check('subquery in FROM', () => {
  const r = parseSql('SELECT * FROM (SELECT user_id, sum(amount) FROM db.orders GROUP BY user_id) t')
  assert.ok(r.tables.includes('db.orders'), `got ${JSON.stringify(r.tables)}`)
})

check('CTE and join', () => {
  const r = parseSql('WITH recent AS (SELECT id, phone FROM db.user WHERE created_at > now() - interval 7 day) SELECT r.phone FROM recent r JOIN db.account a ON a.id = r.id')
  assert.ok(r.tables.includes('db.user'), `got ${JSON.stringify(r.tables)}`)
  assert.ok(r.tables.includes('db.account'), `got ${JSON.stringify(r.tables)}`)
})

check('union branches', () => {
  const r = parseSql('SELECT a FROM db.t1 UNION ALL SELECT a FROM db.t2')
  assert.ok(r.tables.includes('db.t1'))
  assert.ok(r.tables.includes('db.t2'))
})

check('function argument is a column', () => {
  const r = parseSql('SELECT count(*), lower(name) FROM db.user')
  assert.ok(r.columns.includes('name'), `got ${JSON.stringify(r.columns)}`)
})

check('string literals cannot become identifiers', () => {
  const r = parseSql("SELECT name FROM db.user WHERE note = 'from db.secret_table select'")
  assert.ok(!r.tables.includes('db.secret_table'), `leaked: ${JSON.stringify(r.tables)}`)
  assert.ok(!r.columns.includes('select'))
})

check('comments are stripped', () => {
  const r = parseSql('SELECT id FROM db.user -- FROM db.admin\n /* JOIN db.admin */')
  assert.ok(!r.tables.includes('db.admin'), `leaked: ${JSON.stringify(r.tables)}`)
})

check('insert/update/delete marks mutating', () => {
  assert.equal(parseSql("INSERT INTO db.user (name) VALUES ('x')").mutating, true)
  assert.equal(parseSql("UPDATE db.user SET name = 'x' WHERE id = 1").mutating, true)
  assert.equal(parseSql('DELETE FROM db.user WHERE id = 1').mutating, true)
  assert.equal(parseSql('SELECT id FROM db.user').mutating, false)
})

check('non-SQL text is rejected', () => {
  assert.equal(parseSql('hello world how are you').isSql, false)
  assert.equal(parseSql('{"a":1}').isSql, false)
  assert.equal(parseSql('').isSql, false)
})

// ── identifier quoting (regression: backticks once erased the table name) ────
const BT = String.fromCharCode(96)
const ident = name => `${BT}${name}${BT}`

check('backticked table name is still a table', () => {
  const r = parseSql(`SELECT * FROM ${ident('admin')} LIMIT 10`)
  assert.equal(r.isSql, true)
  assert.deepEqual(r.tables, ['admin'], 'a MySQL identifier must not be stripped as a string')
})

check('backticked qualified table keeps both segments', () => {
  assert.deepEqual(parseSql(`SELECT * FROM ${ident('demo')}.${ident('admin')}`).tables, ['demo.admin'])
})

check('backticked columns are resources', () => {
  const r = parseSql(`SELECT ${ident('username')}, ${ident('password_hash')} FROM ${ident('admin')}`)
  assert.ok(r.columns.includes('username'))
  assert.deepEqual(r.tables, ['admin'])
})

check('backticked join target is found', () => {
  const r = parseSql(
    `SELECT a.username FROM ${ident('demo')}.${ident('user')} u`
    + ` JOIN ${ident('demo')}.${ident('admin')} a ON a.id = u.id`,
  )
  assert.deepEqual(r.tables.sort(), ['demo.admin', 'demo.user'])
})

check('bracket identifiers are resources', () => {
  assert.deepEqual(parseSql('SELECT [username] FROM [admin]').tables, ['admin'])
})

check('backtick table is denied by policy', () => {
  const policy = new Policy({
    securityMode: 'blacklist',
    ...mergePolicy({ tables: ['db.admin', 'db.sensitive_log'], columns: [] }, undefined),
  })
  const d = policy.decide(parseSql(`SELECT * FROM ${ident('admin')}`))
  assert.equal(d.allowed, false)
  assert.deepEqual(d.forbiddenTables, ['admin'])
})

check('a string literal cannot smuggle a table', () => {
  const r = parseSql(`SELECT name FROM ${ident('user')} WHERE note = 'FROM admin'`)
  assert.deepEqual(r.tables, ['user'])
})

// ── candidate discovery ─────────────────────────────────────────────────────
check('collects by configured key only', () => {
  const found = collectSqlCandidates(
    { sql: 'SELECT id FROM db.user', path: 'SELECT id FROM db.admin' },
    { keys: ['sql'] },
  )
  assert.equal(found.length, 1)
  assert.equal(found[0].origin, 'sql')
})

check('ignores a non-SQL value under a SQL key', () => {
  assert.equal(collectSqlCandidates({ query: 'explain the numbers' }, { keys: ['query'] }).length, 0)
})
// ── policy: blacklist ───────────────────────────────────────────────────────
const localBlacklist = { tables: ['db.admin', 'db.sensitive_log'], columns: ['db.user.phone', 'db.user.idcard', 'db.user.bank_no'] }
const blacklistPolicy = () => new Policy({ securityMode: 'blacklist', ...mergePolicy(localBlacklist, undefined) })

check('blacklist allows an unlisted table', () => {
  const d = blacklistPolicy().decide(parseSql('SELECT id FROM db.user'))
  assert.equal(d.allowed, true)
})

check('blacklist denies a forbidden table', () => {
  const d = blacklistPolicy().decide(parseSql('SELECT * FROM db.admin'))
  assert.equal(d.allowed, false)
  assert.deepEqual(d.forbiddenTables, ['db.admin'])
})

check('blacklist denies a forbidden column (bare name, qualified policy)', () => {
  const d = blacklistPolicy().decide(parseSql('SELECT phone FROM db.user'))
  assert.equal(d.allowed, false)
  assert.ok(d.forbiddenColumns.includes('phone'), `got ${JSON.stringify(d.forbiddenColumns)}`)
})

check('blacklist table entry governs its columns', () => {
  const d = blacklistPolicy().decide(parseSql('SELECT secret_col FROM db.sensitive_log'))
  assert.equal(d.allowed, false)
})

check('blacklist allows other columns of a mixed table', () => {
  const d = blacklistPolicy().decide(parseSql('SELECT id, name FROM db.user'))
  assert.equal(d.allowed, true)
})

// ── policy: whitelist emulate ───────────────────────────────────────────────
check('whitelist denies without a grant', () => {
  const p = new Policy({ securityMode: 'whitelist_emulate', ...mergePolicy(localBlacklist, undefined) })
  assert.equal(p.decide(parseSql('SELECT id FROM db.user')).allowed, false)
})

check('whitelist denies when no policy exists at all', () => {
  const p = new Policy({ securityMode: 'whitelist_emulate', ...mergePolicy({ tables: [], columns: [] }, undefined) })
  assert.equal(p.decide(parseSql('SELECT id FROM db.user')).allowed, false)
})

check('whitelist grants a table and its columns', () => {
  const p = new Policy({
    securityMode: 'whitelist_emulate',
    ...mergePolicy({ tables: [], columns: [] }, undefined),
    grantedTables: ['db.user'],
    grantedColumns: [],
  })
  assert.equal(p.decide(parseSql('SELECT id, name FROM db.user')).allowed, true)
})

check('whitelist still denies an ungranted table', () => {
  const p = new Policy({
    securityMode: 'whitelist_emulate',
    ...mergePolicy({ tables: [], columns: [] }, undefined),
    grantedTables: ['db.user'],
  })
  const d = p.decide(parseSql('SELECT * FROM db.user JOIN db.pay p ON p.uid = user.id'))
  assert.equal(d.allowed, false)
  assert.ok(d.forbiddenTables.includes('db.pay'))
})

check('whitelist wildcard grant', () => {
  const p = new Policy({
    securityMode: 'whitelist_emulate',
    ...mergePolicy({ tables: [], columns: [] }, undefined),
    grantedTables: ['db.*'],
  })
  assert.equal(p.decide(parseSql('SELECT id FROM db.user')).allowed, true)
})

// Local grants make whitelist mode usable with no policy center at all.
check('local whitelist grants work without a remote', () => {
  const local = { tables: [], columns: [], grantedTables: ['demo.user'], grantedColumns: [] }
  const merged = mergePolicy(local, undefined)
  assert.deepEqual(merged.grantedTables, ['demo.user'], 'local grants survive the merge')
  assert.equal(merged.policySource, 'local')
  assert.equal(merged.hasGrants, true)
  const p = new Policy({ securityMode: 'whitelist_emulate', ...merged })
  assert.equal(p.decide(parseSql('SELECT id, name FROM `demo`.`user`')).allowed, true)
})

check('local whitelist still denies what is not granted', () => {
  const merged = mergePolicy({ tables: [], columns: [], grantedTables: ['demo.user'] }, undefined)
  const p = new Policy({ securityMode: 'whitelist_emulate', ...merged })
  const d = p.decide(parseSql('SELECT * FROM `demo`.`orders`'))
  assert.equal(d.allowed, false)
  assert.ok(d.forbiddenTables.includes('demo.orders'))
})

check('local and remote grants are additive', () => {
  const merged = mergePolicy(
    { tables: [], columns: [], grantedTables: ['demo.user'] },
    { forbiddenTables: [], forbiddenColumns: [], grantedTables: ['demo.product'] },
  )
  assert.deepEqual(merged.grantedTables.sort(), ['demo.product', 'demo.user'])
  assert.equal(merged.policySource, 'local+remote')
})

check('a local whitelist column grant admits just that column', () => {
  const merged = mergePolicy(
    { tables: [], columns: [], grantedTables: ['demo.user_private'], grantedColumns: ['demo.user_private.phone'] },
    undefined,
  )
  const p = new Policy({ securityMode: 'whitelist_emulate', ...merged })
  assert.equal(p.decide(parseSql('SELECT phone FROM `demo`.`user_private`')).allowed, true)
})

check('blacklist mode ignores grants', () => {
  const merged = mergePolicy({ tables: ['db.admin'], columns: [], grantedTables: ['db.admin'] }, undefined)
  const p = new Policy({ securityMode: 'blacklist', ...merged })
  assert.equal(p.decide(parseSql('SELECT * FROM db.admin')).allowed, false, 'a grant must not punch a hole in the blacklist')
})

check('no grants reports hasGrants false so the UI can explain', () => {
  assert.equal(mergePolicy({ tables: [], columns: [] }, undefined).hasGrants, false)
})

// ── the reported bug: a qualified grant vs an unqualified query ─────────────
// Panel entry `demo.user` must admit `FROM user`: a bare table name carries no
// database qualifier to compare, so the more specific grant has to match it.
check('a qualified grant admits an unqualified query', () => {
  const p = new Policy({
    securityMode: 'whitelist_emulate',
    ...mergePolicy({ tables: [], columns: [], grantedTables: ['demo.user'] }, undefined),
  })
  for (const sql of [
    'SELECT * FROM `user`',
    'SELECT id, name FROM user',
    'SELECT COUNT(*) FROM `user`',
    'SELECT 1 FROM user',
  ]) {
    assert.equal(p.decide(parseSql(sql)).allowed, true, `should allow: ${sql}`)
  }
})

check('a qualified grant still denies an unrelated table', () => {
  const p = new Policy({
    securityMode: 'whitelist_emulate',
    ...mergePolicy({ tables: [], columns: [], grantedTables: ['demo.user'] }, undefined),
  })
  assert.equal(p.decide(parseSql('SELECT * FROM orders')).allowed, false)
  assert.equal(p.decide(parseSql('SELECT * FROM `orders`')).allowed, false)
})

// ── the other reported bug: aggregates must not invent a column ─────────────
check('a function name is not a column', () => {
  const r = parseSql('SELECT COUNT(*) FROM `user`')
  assert.deepEqual(r.tables, ['user'])
  assert.deepEqual(r.columns, [], 'COUNT is a callee, not a resource')
})

check('a table name is not re-reported as a column', () => {
  const r = parseSql('SELECT 1 FROM user')
  assert.deepEqual(r.tables, ['user'])
  assert.deepEqual(r.columns, [], 'pass 2 must not re-read the FROM target')
})

check('aggregate over a granted table is allowed in whitelist mode', () => {
  const p = new Policy({
    securityMode: 'whitelist_emulate',
    ...mergePolicy({ tables: [], columns: [], grantedTables: ['demo.user'] }, undefined),
  })
  assert.equal(p.decide(parseSql('SELECT COUNT(*) FROM `user`')).allowed, true)
})

check('function arguments are still inspected', () => {
  const r = parseSql('SELECT lower(name) FROM db.user')
  assert.ok(r.columns.includes('name'), 'the argument is a real column')
})

// ── remote envelope ─────────────────────────────────────────────────────────
check('envelope accepts the documented shape', () => {
  const p = validatePolicyEnvelope({ code: 0, data: { forbiddenTables: ['db.admin'], forbiddenColumns: [] } })
  assert.deepEqual(p.forbiddenTables, ['db.admin'])
})

check('envelope keeps granted lists when present', () => {
  const p = validatePolicyEnvelope({ code: 0, data: { forbiddenTables: [], forbiddenColumns: [], grantedTables: ['db.user'] } })
  assert.deepEqual(p.grantedTables, ['db.user'])
})

check('envelope rejects a non-zero code', () => {
  assert.throws(() => validatePolicyEnvelope({ code: 401, data: {} }))
})

check('envelope rejects a missing data object', () => {
  assert.throws(() => validatePolicyEnvelope({ code: 0 }))
})

check('mergePolicy labels the source', () => {
  assert.equal(mergePolicy(localBlacklist, undefined).policySource, 'local')
  assert.equal(mergePolicy(localBlacklist, { forbiddenTables: [], forbiddenColumns: [] }).policySource, 'local+remote')
})

// ── remote client ───────────────────────────────────────────────────────────
check('remote client caches within the TTL', async () => {
  let calls = 0
  const client = new RemotePolicyClient(
    { policyApiUrl: 'http://policy.test/api', policyApiToken: 't', apiTimeoutMs: 1000, cacheTtlMs: 30000 },
    {
      now: () => 1000,
      fetchImpl: async () => { calls += 1; return { status: 200, json: async () => ({ code: 0, data: { forbiddenTables: ['db.admin'], forbiddenColumns: [] } }) } },
    },
  )
  await client.read()
  await client.read()
  assert.equal(calls, 1, 'second read must be served from cache')
})

check('remote client sends bearer token and query parameters', async () => {
  let seen
  const client = new RemotePolicyClient(
    { policyApiUrl: 'http://policy.test/api', policyApiToken: 'sekret', apiTimeoutMs: 1000, cacheTtlMs: 30000, tenantId: 't1', userId: 'u1' },
    { now: () => 0, fetchImpl: async (url, init) => { seen = { url: String(url), init }; return { status: 200, json: async () => ({ code: 0, data: { forbiddenTables: [], forbiddenColumns: [] } }) } } },
  )
  await client.read()
  assert.ok(seen.url.includes('tenantId=t1'))
  assert.ok(seen.url.includes('userId=u1'))
  assert.equal(seen.init.headers.authorization, 'Bearer sekret')
})

check('remote client fails closed on HTTP 500', async () => {
  const client = new RemotePolicyClient(
    { policyApiUrl: 'http://policy.test/api', policyApiToken: '', apiTimeoutMs: 1000, cacheTtlMs: 30000 },
    { now: () => 0, fetchImpl: async () => ({ status: 500, json: async () => ({}) }) },
  )
  await assert.rejects(() => client.read())
})

console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed === 0 ? 0 : 1)
