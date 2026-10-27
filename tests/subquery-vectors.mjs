// VULN-04 regression suite: subqueries must be found wherever they live.
//
// The second-round report found that an authorised outer table plus an
// unauthorised subquery read arbitrary rows. The cause was slot enumeration:
// the extractor read `from` / `columns` / `table`, but never `where` / `having`,
// so `SELECT (SELECT idcard FROM user_private …) FROM demo.user` produced
// `tables: ['demo.user']` and sailed through.
//
// The fix walks the whole AST instead. These cases pin every position a
// subquery can occupy, plus the cross-database confusion that the walk exposed.
import assert from 'node:assert/strict'
import { parseSql, collectSqlCandidates } from '../src/sql-parse.js'
import { Policy, mergePolicy } from '../src/policy.js'

/** Whitelist: demo.user only. */
const allowUserOnly = () => new Policy({
  securityMode: 'whitelist_emulate',
  ...mergePolicy({ tables: [], columns: [], grantedTables: ['demo.user'] }, undefined),
})

/** Decide one statement. */
function decide(policy, sql) {
  const candidates = collectSqlCandidates({ sql }, { keys: ['sql'] })
  if (candidates.length === 0) return { verdict: 'NO-CANDIDATE', parsed: undefined }
  const parsed = candidates[0].parsed
  return { verdict: policy.decide(parsed).allowed ? 'ALLOW' : 'DENY', parsed }
}

const cases = []
const check = (label, fn) => cases.push({ label, fn })

// ── every position a subquery can occupy ───────────────────────────────────
const SUBQUERY_VECTORS = [
  ['SELECT 子查询 (标量)', 'SELECT (SELECT idcard FROM user_private LIMIT 1) AS leak FROM demo.user LIMIT 1'],
  ['SELECT 子查询 (多列)', 'SELECT (SELECT phone FROM user_private LIMIT 1) AS p, (SELECT bank_no FROM user_private LIMIT 1) AS b FROM demo.user LIMIT 1'],
  ['SELECT 子查询 (口令哈希)', 'SELECT (SELECT password_hash FROM admin LIMIT 1) AS h FROM demo.user LIMIT 1'],
  ['SELECT 子查询带 WHERE', 'SELECT (SELECT address FROM user_private WHERE user_id=1) AS a FROM demo.user LIMIT 1'],
  ['WHERE IN 子查询', 'SELECT * FROM demo.user WHERE id IN (SELECT user_id FROM user_private)'],
  ['WHERE 标量子查询', 'SELECT (SELECT COUNT(*) FROM admin) AS admin_rows FROM demo.user LIMIT 2'],
  ['WHERE EXISTS 子查询', "SELECT id FROM demo.user WHERE EXISTS (SELECT 1 FROM admin WHERE username LIKE 'a%')"],
  ['系统库子查询', 'SELECT (SELECT COUNT(*) FROM mysql.user) AS n FROM demo.user LIMIT 1'],
  ['嵌套两层', 'SELECT * FROM demo.user WHERE id IN (SELECT id FROM demo.user WHERE id IN (SELECT user_id FROM user_private))'],
  ['HAVING 子查询', 'SELECT level FROM demo.user GROUP BY level HAVING COUNT(*) > (SELECT COUNT(*) FROM admin)'],
  ['UNION 分支', 'SELECT * FROM demo.user UNION SELECT * FROM user_private'],
  ['派生表', 'SELECT * FROM (SELECT user_id FROM user_private) t'],
  ['JOIN', 'SELECT u.id FROM demo.user u JOIN demo.user_private p ON p.user_id = u.id'],
  ['WHERE BETWEEN 子查询', 'SELECT * FROM demo.user WHERE id BETWEEN (SELECT MIN(user_id) FROM user_private) AND 99'],
  ['WHERE 比较子查询', 'SELECT * FROM demo.user WHERE id > (SELECT MIN(user_id) FROM admin)'],
  ['ORDER BY 子查询', 'SELECT id FROM demo.user ORDER BY (SELECT COUNT(*) FROM admin)'],
  ['嵌套 IN 三层', 'SELECT * FROM demo.user WHERE id IN (SELECT id FROM demo.user WHERE id IN (SELECT id FROM demo.user WHERE id IN (SELECT user_id FROM admin)))'],
]

for (const [label, sql] of SUBQUERY_VECTORS) {
  check(`VULN-04 ${label} 被拒绝`, () => {
    const { verdict, parsed } = decide(allowUserOnly(), sql)
    assert.equal(verdict, 'DENY', `${sql}\n  tables=${JSON.stringify(parsed?.tables)}`)
  })
}

check('VULN-04 子查询里的表确实进入资源集', () => {
  const { parsed } = decide(allowUserOnly(), 'SELECT * FROM demo.user WHERE id IN (SELECT user_id FROM user_private)')
  assert.deepEqual(parsed.tables.sort(), ['demo.user', 'user_private'])
})

check('VULN-04 多层嵌套的全部表都被收集', () => {
  const { parsed } = decide(
    allowUserOnly(),
    'SELECT * FROM demo.user WHERE id IN (SELECT id FROM demo.user WHERE id IN (SELECT user_id FROM admin))',
  )
  assert.deepEqual(parsed.tables.sort(), ['admin', 'demo.user'])
})

// ── the cross-database confusion the walk exposed ──────────────────────────
check('授权项带库名时不得匹配其他库的同名表', () => {
  // `demo.user` used to admit `mysql.user` because the matcher trimmed the
  // entry's leading segment to fit a shorter resource.
  assert.equal(decide(allowUserOnly(), 'SELECT * FROM mysql.user').verdict, 'DENY')
  assert.equal(decide(allowUserOnly(), 'SELECT * FROM information_schema.tables').verdict, 'DENY')
  assert.equal(decide(allowUserOnly(), 'SELECT * FROM demo.user').verdict, 'ALLOW')
})

check('授权项带库名时仍匹配裸表名', () => {
  // An unqualified query carries no database to compare, so the grant must
  // still apply — this is the behaviour the trim existed to provide.
  assert.equal(decide(allowUserOnly(), 'SELECT * FROM user').verdict, 'ALLOW')
})

check('黑名单带库名时也不误伤其他库', () => {
  const policy = new Policy({
    securityMode: 'blacklist',
    ...mergePolicy({ tables: ['demo.admin'], columns: [] }, undefined),
  })
  assert.equal(decide(policy, 'SELECT * FROM demo.admin').verdict, 'DENY')
  assert.equal(decide(policy, 'SELECT * FROM otherdb.admin').verdict, 'ALLOW')
  assert.equal(decide(policy, 'SELECT * FROM admin').verdict, 'DENY')
})

// ── no false positives on ordinary queries ─────────────────────────────────
check('普通查询不受影响', () => {
  for (const sql of [
    'SELECT id, name FROM demo.user',
    'SELECT COUNT(*) FROM demo.user',
    'SELECT * FROM demo.user WHERE id = 1',
    'SELECT level, COUNT(*) FROM demo.user GROUP BY level',
  ]) {
    const { parsed } = decide(allowUserOnly(), sql)
    assert.deepEqual(parsed.tables, ['demo.user'], sql)
  }
  // A JOIN legitimately reads two tables; both must be discovered.
  const joined = decide(allowUserOnly(), 'SELECT u.name, o.amount FROM demo.user u JOIN demo.orders o ON o.user_id = u.id')
  assert.deepEqual(joined.parsed.tables.sort(), ['demo.orders', 'demo.user'])
})

check('别名不会出现在表集合里', () => {
  const { parsed } = decide(allowUserOnly(), 'SELECT u.id FROM demo.user u JOIN demo.orders o ON o.user_id = u.id')
  assert.deepEqual(parsed.tables.sort(), ['demo.orders', 'demo.user'], 'aliases u/o must not be tables')
})

check('CTE 名仍然不是物理表', () => {
  const { parsed } = decide(
    allowUserOnly(),
    'WITH recent AS (SELECT id FROM demo.user) SELECT * FROM recent',
  )
  assert.deepEqual(parsed.tables, ['demo.user'], 'the CTE name `recent` is not a table')
})

check('列引用不被误当表', () => {
  const { parsed } = decide(allowUserOnly(), 'SELECT demo.user.id FROM demo.user')
  assert.deepEqual(parsed.tables, ['demo.user'])
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
