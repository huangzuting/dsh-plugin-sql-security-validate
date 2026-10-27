// Third-round report items: the bare-grant trap and the strict gate that closes it.
//
// The report found that a whitelist written with a bare table name (`user`)
// also grants `mysql.user`, because a bare entry aligns against a qualified
// resource's tail. It is a configuration trap rather than a code defect — a bare
// name genuinely carries no database — so the fix is a config validator, a UI
// warning, documentation, and an opt-in `strictDatabaseQualification` gate.
import assert from 'node:assert/strict'
import { Policy, mergePolicy } from '../src/policy.js'

/** Grant matching honouring the strict flag. */
const granted = (resource, grants, strict = false) => Policy.grantedBy(resource, grants, strict)

const cases = []
const check = (label, fn) => cases.push({ label, fn })

// ── 7.1 the trap, reproduced exactly as reported ───────────────────────────
check('裸授权项按默认设置会跨库（报告现象复现）', () => {
  assert.equal(granted('user', ['user']), true)
  assert.equal(granted('demo.user', ['user']), true)
  // The reported over-reach: a bare grant reaches other databases.
  assert.equal(granted('mysql.user', ['user']), true, '默认宽容，报告描述属实')
  assert.equal(granted('agentos.user', ['user']), true)
  assert.equal(granted('newapi.user', ['user']), true)
})

check('strictDatabaseQualification 关闭该跨库（报告 7.4-3 的开关）', () => {
  assert.equal(granted('user', ['user'], true), true, '裸名查询仍放行')
  assert.equal(granted('mysql.user', ['user'], true), false, '不再跨库')
  assert.equal(granted('agentos.user', ['user'], true), false)
  assert.equal(granted('newapi.user', ['user'], true), false)
})

check('strict 不影响带库名的授权项', () => {
  // `demo.user` is unambiguous, so the gate must not change its behaviour.
  assert.equal(granted('user', ['demo.user'], true), true, '裸名查询仍可按库匹配')
  assert.equal(granted('demo.user', ['demo.user'], true), true)
  assert.equal(granted('mysql.user', ['demo.user'], true), false)
})

check('strict 下裸授权项不再匹配裸名以外的一切', () => {
  assert.equal(granted('user', ['user'], true), true)
  assert.equal(granted('demo.user', ['user'], true), false, '带库名的引用被拒绝')
})

// ── the gate is wired through Policy, not only the static helper ───────────
check('Policy 在 strict 下拒绝跨库查询', () => {
  const policy = new Policy({
    securityMode: 'whitelist_emulate',
    grantedTables: ['user'],
    strictDatabaseQualification: true,
  })
  const decide = tables => policy.decide({ tables, columns: [] }).allowed
  assert.equal(decide(['user']), true)
  assert.equal(decide(['mysql.user']), false)
  assert.equal(decide(['demo.user']), false)
})

check('Policy 在默认设置下保持原语义', () => {
  const policy = new Policy({
    securityMode: 'whitelist_emulate',
    grantedTables: ['user'],
    strictDatabaseQualification: false,
  })
  const decide = tables => policy.decide({ tables, columns: [] }).allowed
  assert.equal(decide(['user']), true)
  assert.equal(decide(['demo.user']), true)
  assert.equal(decide(['mysql.user']), true, '默认宽容，与报告描述一致')
})

// ── the recommended configuration is safe either way ──────────────────────
check('推荐写法（库名.表名）在两种设置下都安全', () => {
  for (const strict of [false, true]) {
    assert.equal(granted('demo.user', ['demo.user'], strict), true)
    assert.equal(granted('mysql.user', ['demo.user'], strict), false)
    assert.equal(granted('demo.user_private', ['demo.user'], strict), false)
    assert.equal(granted('admin', ['demo.user'], strict), false)
  }
})

// ── enforcement side must keep its opposite tolerance ─────────────────────
check('黑名单的裸名仍覆盖带库名的资源', () => {
  // The reverse direction must NOT be restricted: `admin` has to block
  // `demo.admin`, which is exactly what enforcement is for.
  assert.equal(Policy.coveredBy('demo.admin', ['admin']), true)
  assert.equal(Policy.coveredBy('admin', ['admin']), true)
  assert.equal(Policy.coveredBy('mysql.admin', ['admin']), true)
})

check('黑名单带库名时不误伤其他库', () => {
  assert.equal(Policy.coveredBy('demo.admin', ['demo.admin']), true)
  assert.equal(Policy.coveredBy('otherdb.admin', ['demo.admin']), false)
})

// ── grantedBy must be defined exactly once (report §8 item 1) ────────────
check('grantedBy 只有一个定义', async () => {
  const { readFileSync } = await import('node:fs')
  const source = readFileSync(new URL('../src/policy.js', import.meta.url), 'utf8')
  const definitions = source.match(/static grantedBy\s*\(/g) ?? []
  assert.equal(definitions.length, 1, `expected one definition, found ${definitions.length}`)
})

let passed = 0
let failed = 0
for (const { label, fn } of cases) {
  try {
    await fn()
    passed += 1
  } catch (error) {
    failed += 1
    console.log(`FAIL  ${label}\n      ${String(error.message).split('\n').join('\n      ')}`)
  }
}
console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed === 0 ? 0 : 1)
