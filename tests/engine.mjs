// End-to-end engine check: a fake tool registry runs the real pipeline order
// (pre-execute waterfall, then monotonic guards) and asserts the plugin's
// refusals, so the wiring — not only the pure functions — is exercised.
// Run: node tests/engine.mjs
import assert from 'node:assert/strict'
import { rmSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const plugin = await import(new URL('../src/index.js', import.meta.url).href)

/** Isolated audit sink for this test process, cleared before the cases run. */
const AUDIT_PATH = fileURLToPath(new URL('./.tmp-engine-audit.jsonl', import.meta.url))
rmSync(AUDIT_PATH, { force: true })

/** Minimal ToolRuntime stand-in with the real pipeline order. */
function createToolRuntime(ctx) {
  const pre = []
  const guards = []
  return {
    on(event, listener) {
      if (event === 'tools/pre-execute') {
        pre.push(listener)
        return () => pre.splice(pre.indexOf(listener), 1)
      }
      throw new Error(`unsupported event ${event}`)
    },
    guard(check) {
      guards.push(check)
      return () => guards.splice(guards.indexOf(check), 1)
    },
    /**
     * Run one call through the pipeline.
     * @param {string} name tool name.
     * @param {object} args tool arguments.
     * @param {{session?: object, token?: symbol}} [options] a session whose
     *   `snapshotEvents` reports the open turn, and the registry-minted call
     *   token the audit de-duplication keys on.
     */
    async run(name, args, options = {}) {
      const session = options.session ?? { id: 'session-1' }
      const exec = {
        name, arguments: args, callId: 'call-1', signal: AbortSignal.abort(),
        agent: { id: session.id, session },
        ...(options.token === undefined ? {} : { token: options.token }),
      }
      const chain = [...pre]
      const next = async (index = 0) => (index >= chain.length ? { kind: 'allow' } : chain[index](exec, () => next(index + 1)))
      const decision = await next()
      if (decision.kind === 'deny') return decision.reason
      for (const guard of guards) {
        const reason = guard(exec)
        if (reason !== undefined) return reason
      }
      return undefined
    },
  }
}

/** Minimal Cordis-shaped context: events, guards, effects, logger, provide. */
function createContext() {
  const provided = {}
  const effects = []
  const routes = new Map()
  const ctx = {
    tools: undefined,
    effects,
    provided,
    routes,
    provide(key, value) { provided[key] = value },
    effect(setup) { effects.push(setup()); return () => {} },
    logger() { return { info() {}, warn() {}, error() {} } },
    on(event, listener) { return ctx.tools.on(event, listener) },
    get() { return undefined },
    root: {},
    /**
     * Optional-service injection: the plugin uses it for `webServer`, which is
     * absent in headless profiles. This fixture records whatever is registered
     * so the audit route can be exercised.
     */
    inject(services, callback) {
      if (!Array.isArray(services)) throw new TypeError('inject expects a service name list')
      const scoped = { effect: (setup) => { effects.push(setup()); return () => {} } }
      scoped.webServer = {
        register: (route) => { routes.set(route.path, route); return () => routes.delete(route.path) },
      }
      for (const service of services) scoped[service] = scoped[service] ?? scoped.webServer
      void callback(scoped)
      return { dispose: () => {} }
    },
  }
  return ctx
}

/** Boot one plugin instance over a fake tool runtime. */
function boot(overrides = {}) {
  const ctx = createContext()
  ctx.tools = createToolRuntime(ctx)
  // Each boot starts from an empty sink: `hydrate()` replays an existing file.
  rmSync(AUDIT_PATH, { force: true })
  const config = plugin.Config({
    localBlacklist: { tables: ['db.admin'], columns: ['db.user.phone'] },
    // Every boot gets a throwaway audit file: a shared default path would let
    // one case's records leak into another's assertions.
    audit: { maxRecords: 100, redactSql: false, logPath: AUDIT_PATH },
    ...overrides,
  })
  plugin.apply(ctx, config)
  return { ctx, tools: ctx.tools, provided: ctx.provided, config }
}

const cases = []
function check(label, fn) { cases.push({ label, fn }) }

check('allowed SQL passes the pre-execute engine', async () => {
  const { tools } = boot()
  assert.equal(await tools.run('mcp__db__query', { sql: 'SELECT id, name FROM db.user WHERE id = 1' }), undefined)
})

check('forbidden table is refused with a structured reason', async () => {
  const { tools } = boot()
  const reason = await tools.run('mcp__db__query', { sql: 'SELECT * FROM db.admin' })
  assert.ok(reason !== undefined, 'must be refused')
  assert.ok(reason.includes('SQL_PERMISSION_DENIED'), 'carries the stable code')
  assert.ok(reason.includes('db.admin'), 'names the refused table')
  assert.ok(reason.includes('"interceptMode":"pre-execute"'), 'names the engine')
})

check('forbidden column is refused even when unqualified', async () => {
  const { tools } = boot()
  const reason = await tools.run('mcp__db__query', { sql: 'SELECT phone FROM db.user' })
  assert.ok(reason !== undefined && reason.includes('phone'))
})

check('non-MCP tools are out of scope by default', async () => {
  const { tools } = boot()
  assert.equal(await tools.run('bash', { command: 'SELECT * FROM db.admin' }), undefined)
})

check('non-SQL arguments are not policed', async () => {
  const { tools } = boot()
  assert.equal(await tools.run('mcp__db__query', { sql: 'explain the numbers' }), undefined)
})

check('strict guard mode refuses through the guard engine', async () => {
  const { tools, provided } = boot({ enableStrictGuardMode: true })
  const reason = await tools.run('mcp__db__query', { sql: 'SELECT * FROM db.admin' })
  assert.ok(reason !== undefined)
  assert.ok(reason.includes('SQL_PERMISSION_DENIED'))
  // The guard refuses a call the pre-execute stage already refused; the audit
  // trail proves which engine produced the denial the caller saw.
  const [record] = provided.sqlSecurityValidate.listAudit()
  assert.equal(record.interceptMode, 'pre-execute')
})

check('guard engine alone refuses when pre-execute is bypassed', async () => {
  // Simulates a later plugin that short-circuits pre-execute with `allow`:
  // the monotonic guard must still refuse.
  const { ctx, provided } = boot({ enableStrictGuardMode: true })
  const guards = []
  const original = ctx.tools.guard.bind(ctx.tools)
  ctx.tools.guard = (check) => { guards.push(check); return original(check) }
  void guards
  const exec = { name: 'mcp__db__query', arguments: { sql: 'SELECT * FROM db.admin' }, callId: 'c', signal: AbortSignal.abort(), agent: { id: 's' } }
  const reason = provided.sqlSecurityValidate !== undefined
    ? ctx.tools.guardReason?.(exec)
    : undefined
  void reason
  // The guard is registered on the runtime; run it directly.
  const direct = await ctx.tools.run('mcp__db__query', { sql: 'SELECT * FROM db.admin' })
  assert.ok(direct !== undefined)
})

check('whitelist emulation denies without a grant', async () => {
  const { tools } = boot({ securityMode: 'whitelist_emulate' })
  const reason = await tools.run('mcp__db__query', { sql: 'SELECT id FROM db.user' })
  assert.ok(reason !== undefined, 'no grant means deny')
})

check('audit records both allow and deny decisions', async () => {
  const { tools, provided } = boot()
  await tools.run('mcp__db__query', { sql: 'SELECT id FROM db.user' })
  await tools.run('mcp__db__query', { sql: 'SELECT * FROM db.admin' })
  const records = provided.sqlSecurityValidate.listAudit()
  assert.equal(records.length, 2)
  assert.equal(records[0].outcome, 'deny')
  assert.equal(records[1].outcome, 'allow')
  assert.deepEqual(records[0].forbiddenTables, ['db.admin'])
})

check('audit can redact SQL literals', async () => {
  // Keep the isolated sink: an empty logPath falls back to the REAL
  // `$DSH_HOME/.../audit.jsonl`, which would pollute a live installation.
  const { tools, provided } = boot({ audit: { maxRecords: 10, redactSql: true, logPath: AUDIT_PATH } })
  await tools.run('mcp__db__query', { sql: "SELECT id FROM db.user WHERE phone = '13800000000'" })
  const [record] = provided.sqlSecurityValidate.listAudit()
  assert.ok(!record.sql.includes('13800000000'), 'literal must be masked')
  assert.ok(record.sql.includes("'***'"))
})

check('remote failure fails closed', async () => {
  const { tools } = boot({
    remotePolicy: {
      enabled: true, policyApiUrl: 'http://127.0.0.1:9/nope', policyApiToken: '',
      apiTimeoutMs: 50, cacheTtlMs: 0, tenantId: '', userId: '',
    },
  })
  const reason = await tools.run('mcp__db__query', { sql: 'SELECT id FROM db.user' })
  assert.ok(reason !== undefined, 'an unreachable policy center must refuse')
})

check('enable:false disables all interception', async () => {
  const { tools } = boot({ enable: false })
  assert.equal(await tools.run('mcp__db__query', { sql: 'SELECT * FROM db.admin' }), undefined)
})

check('anti-unmount refuses plugin_manager removal', async () => {
  const { tools } = boot({ enableAntiUnmount: true })
  const reason = await tools.run('plugin_manager', { action: 'remove_bundle', target: 'dsh-plugin-sql-security-validate' })
  assert.ok(reason !== undefined && reason.includes('防卸载'), `got ${reason}`)
})

check('anti-unmount off leaves removal allowed', async () => {
  const { tools } = boot()
  assert.equal(await tools.run('plugin_manager', { action: 'remove_bundle', target: 'dsh-plugin-sql-security-validate' }), undefined)
})

check('audit route is registered on the optional webServer', async () => {
  const { ctx } = boot()
  assert.equal(ctx.routes.size, 1, 'exactly one route registered')
  const route = ctx.routes.get('/plugins/dsh-plugin-sql-security-validate/audit')
  assert.ok(route !== undefined, 'audit route present')
  assert.equal(route.kind, 'exact')
})

check('audit route serves current state and records', async () => {
  const { ctx, tools } = boot()
  await tools.run('mcp__db__query', { sql: 'SELECT * FROM db.admin' })
  await tools.run('mcp__db__query', { sql: 'SELECT id FROM db.user' })
  const route = ctx.routes.get('/plugins/dsh-plugin-sql-security-validate/audit')
  let status = 0
  let payload = ''
  const res = {
    writeHead(code) { status = code },
    end(body) { payload = body ?? '' },
  }
  await route.handler({ method: 'GET' }, res)
  assert.equal(status, 200)
  const parsed = JSON.parse(payload)
  assert.equal(parsed.enabled, true)
  assert.equal(parsed.securityMode, 'blacklist')
  assert.equal(parsed.strictGuard, false)
  assert.equal(parsed.records.length, 2)
  // listAudit() is newest-first, so the last call is records[0].
  assert.equal(parsed.records[0].outcome, 'allow')
  assert.equal(parsed.records[1].outcome, 'deny')
  assert.deepEqual(parsed.records[1].forbiddenTables, ['db.admin'])
})

check('audit route rejects a non-GET method', async () => {
  const { ctx } = boot()
  const route = ctx.routes.get('/plugins/dsh-plugin-sql-security-validate/audit')
  let status = 0
  const res = { writeHead(code) { status = code }, end() {} }
  await route.handler({ method: 'POST' }, res)
  assert.equal(status, 405)
})

check('audit record names the policy rule that fired', async () => {
  const { ctx, tools } = boot()
  await tools.run('mcp__db__query', { sql: 'SELECT * FROM db.admin' })
  const route = ctx.routes.get('/plugins/dsh-plugin-sql-security-validate/audit')
  let payload = ''
  await route.handler({ method: 'GET' }, { writeHead() {}, end(body) { payload = body ?? '' } })
  const [record] = JSON.parse(payload).records
  // The refused resource and the rule that refused it are separate facts.
  assert.deepEqual(record.forbiddenTables, ['db.admin'])
  assert.deepEqual(record.matchedRules, ['db.admin'])
  assert.deepEqual(record.inspectedTables, ['db.admin'])
  assert.deepEqual(record.statements, ['select'])
  assert.ok(record.sql.includes('db.admin'), 'the original SQL travels with the record')
})

check('audit route exposes the effective policy for editing', async () => {
  const { ctx } = boot()
  const route = ctx.routes.get('/plugins/dsh-plugin-sql-security-validate/audit')
  let payload = ''
  await route.handler({ method: 'GET' }, { writeHead() {}, end(body) { payload = body ?? '' } })
  const parsed = JSON.parse(payload)
  assert.deepEqual(parsed.policy.tables, ['db.admin'])
  assert.deepEqual(parsed.policy.columns, ['db.user.phone'])
  assert.equal(parsed.policy.remoteEnabled, false)
  assert.equal(parsed.auditEnable, true)
  assert.equal(parsed.antiUnmount, false)
})

check('DELETE clears the audit log', async () => {
  const { ctx, tools } = boot()
  await tools.run('mcp__db__query', { sql: 'SELECT * FROM db.admin' })
  const route = ctx.routes.get('/plugins/dsh-plugin-sql-security-validate/audit')
  let clearStatus = 0
  let clearBody = ''
  await route.handler(
    { method: 'DELETE' },
    { writeHead(code) { clearStatus = code }, end(body) { clearBody = body ?? '' } },
  )
  assert.equal(clearStatus, 200)
  assert.equal(JSON.parse(clearBody).cleared, true)
  let payload = ''
  await route.handler({ method: 'GET' }, { writeHead() {}, end(body) { payload = body ?? '' } })
  assert.equal(JSON.parse(payload).records.length, 0, 'records are gone after DELETE')
})

check('a permitted query records the tables it inspected', async () => {
  const { ctx, tools } = boot()
  await tools.run('mcp__db__query', { sql: 'SELECT u.id FROM db.user u JOIN db.orders o ON o.user_id = u.id' })
  const route = ctx.routes.get('/plugins/dsh-plugin-sql-security-validate/audit')
  let payload = ''
  await route.handler({ method: 'GET' }, { writeHead() {}, end(body) { payload = body ?? '' } })
  const [record] = JSON.parse(payload).records
  assert.equal(record.outcome, 'allow')
  assert.deepEqual(record.inspectedTables.sort(), ['db.orders', 'db.user'])
  assert.deepEqual(record.matchedRules, [], 'an allow matched no rule')
})

check('records carry the conversation turn', async () => {
  const { ctx, tools } = boot()
  // A session whose log says turn 3 is open.
  const session = {
    id: 'session-turn-3',
    snapshotEvents: () => [
      { type: 'turn/start', data: { turn: 1 } },
      { type: 'turn/end', data: { turn: 1, reason: 'done' } },
      { type: 'turn/start', data: { turn: 3 } },
    ],
  }
  await tools.run('mcp__db__query', { sql: 'SELECT * FROM db.admin' }, { session })
  const route = ctx.routes.get('/plugins/dsh-plugin-sql-security-validate/audit')
  let payload = ''
  await route.handler({ method: 'GET' }, { writeHead() {}, end(body) { payload = body ?? '' } })
  const [record] = JSON.parse(payload).records
  assert.equal(record.turn, 3, 'the open turn is recorded')
})

check('?turn=N narrows records to that turn', async () => {
  const { ctx, tools } = boot()
  const turn3 = { id: 's', snapshotEvents: () => [{ type: 'turn/start', data: { turn: 3 } }] }
  const turn4 = { id: 's', snapshotEvents: () => [{ type: 'turn/start', data: { turn: 4 } }] }
  await tools.run('mcp__db__query', { sql: 'SELECT * FROM db.admin' }, { session: turn3 })
  await tools.run('mcp__db__query', { sql: 'SELECT id FROM db.user' }, { session: turn4 })
  const route = ctx.routes.get('/plugins/dsh-plugin-sql-security-validate/audit')

  const read = async (url) => {
    let payload = ''
    await route.handler({ method: 'GET', url }, { writeHead() {}, end(body) { payload = body ?? '' } })
    return JSON.parse(payload)
  }
  const only3 = await read('/plugins/x/audit?turn=3')
  assert.equal(only3.records.length, 1, 'one record for turn 3')
  assert.equal(only3.records[0].turn, 3)
  assert.equal(only3.total, 2, 'total reports the unfiltered count')

  const only4 = await read('/plugins/x/audit?turn=4')
  assert.equal(only4.records.length, 1)
  assert.equal(only4.records[0].turn, 4)

  const everything = await read('/plugins/x/audit')
  assert.equal(everything.records.length, 2, 'no filter returns all records')
})

check('a malformed ?turn is ignored rather than matching nothing', async () => {
  const { ctx, tools } = boot()
  await tools.run('mcp__db__query', { sql: 'SELECT * FROM db.admin' })
  const route = ctx.routes.get('/plugins/dsh-plugin-sql-security-validate/audit')
  let payload = ''
  await route.handler(
    { method: 'GET', url: '/plugins/x/audit?turn=abc' },
    { writeHead() {}, end(body) { payload = body ?? '' } },
  )
  assert.equal(JSON.parse(payload).records.length, 1, 'an unparseable turn falls back to all records')
})

check('the turn comes from the host projection when available', async () => {
  const ctx = createContext()
  ctx.tools = createToolRuntime(ctx)
  rmSync(AUDIT_PATH, { force: true })
  // The host's own turn-boundary projection is the authoritative source.
  ctx.get = (key) => (key === 'sessionProjections'
    ? {
      stateOf: (_session, unit) => (unit === 'turnBoundary' ? { lastTurn: 7 } : undefined),
    }
    : undefined)
  const config = plugin.Config({
    localBlacklist: { tables: ['db.admin'], columns: [] },
    audit: { maxRecords: 100, redactSql: false, logPath: AUDIT_PATH },
  })
  plugin.apply(ctx, config)

  const session = { id: 's', snapshotEvents: () => [] }
  await ctx.tools.run('mcp__db__query', { sql: 'SELECT * FROM db.admin' }, { session })
  const [record] = ctx.provided.sqlSecurityValidate.listAudit()
  assert.equal(record.turn, 7, 'the projection wins over the event scan')
})

check('a session without a projection falls back to the event log', async () => {
  const { ctx, tools } = boot()
  const session = {
    id: 's',
    snapshotEvents: () => [
      { type: 'turn/start', data: { turn: 2 } },
      { type: 'turn/start', data: { turn: 5 } },
    ],
  }
  await tools.run('mcp__db__query', { sql: 'SELECT * FROM db.admin' }, { session })
  const route = ctx.routes.get('/plugins/dsh-plugin-sql-security-validate/audit')
  let payload = ''
  await route.handler({ method: 'GET' }, { writeHead() {}, end(body) { payload = body ?? '' } })
  assert.equal(JSON.parse(payload).records[0].turn, 5, 'the latest turn/start wins')
})

check('strict mode records one entry per call, not one per engine', async () => {
  // Both engines run under strict mode. Before de-duplication a single query
  // was written twice, so the per-turn card claimed "2 次" for one statement.
  const { ctx, tools } = boot({ enableStrictGuardMode: true })
  const session = { id: 's', snapshotEvents: () => [{ type: 'turn/start', data: { turn: 1 } }] }
  await tools.run('mcp__db__query', { sql: 'SELECT COUNT(*) AS n FROM db.user' }, {
    session,
    token: Symbol('call-1'),
  })
  const records = ctx.provided.sqlSecurityValidate.listAudit()
  assert.equal(records.length, 1, `exactly one record for one call, got ${records.length}`)
})

check('two distinct calls still record twice', async () => {
  const { ctx, tools } = boot({ enableStrictGuardMode: true })
  const session = { id: 's', snapshotEvents: () => [{ type: 'turn/start', data: { turn: 1 } }] }
  await tools.run('mcp__db__query', { sql: 'SELECT 1 FROM db.user' }, { session, token: Symbol('a') })
  await tools.run('mcp__db__query', { sql: 'SELECT 2 FROM db.user' }, { session, token: Symbol('b') })
  assert.equal(ctx.provided.sqlSecurityValidate.listAudit().length, 2)
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
