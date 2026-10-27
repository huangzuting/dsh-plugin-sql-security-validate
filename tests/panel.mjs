// Render smoke test for the settings panel and the per-turn card: a minimal
// React stand-in renders each component for the states that matter, so a broken
// branch is caught here instead of blanking a slot in the browser.
// Run: node tests/panel.mjs
import assert from 'node:assert/strict'

/** Minimal React: enough of createElement/useState to render one tree. */
function makeReact(seed) {
  const states = []
  const effects = []
  let cursor = 0
  const createElement = (type, props, ...children) => ({
    type: typeof type === 'function' ? type.name || 'Component' : String(type),
    fn: typeof type === 'function' ? type : undefined,
    props: { ...(props ?? {}), children: children.length === 1 ? children[0] : children },
    key: props?.key,
  })
  const render = (node) => {
    if (node === null || node === undefined) return ''
    if (typeof node === 'string' || typeof node === 'number') return String(node)
    if (Array.isArray(node)) return node.map(render).join('')
    if (typeof node === 'object' && node.fn) {
      cursor = 0
      return render(node.fn({ ...node.props, children: undefined }))
    }
    if (typeof node === 'object' && node.props) return render(node.props.children)
    return ''
  }
  return {
    createElement,
    Fragment: Symbol('Fragment'),
    useState: (initial) => {
      const index = cursor++
      if (states[index] === undefined) {
        states[index] = seed?.[index] ?? (typeof initial === 'function' ? initial() : initial)
      }
      return [states[index], (next) => {
        states[index] = typeof next === 'function' ? next(states[index]) : next
      }]
    },
    /** Replace the whole state table, for a case that renders from a known state. */
    seed: (values) => {
      states.length = 0
      for (const value of values) states.push(value)
      cursor = 0
    },
    useEffect: (fn) => { effects.push(fn) },
    useCallback: (fn) => fn,
    pendingEffects: effects,
    render,
    reset: () => { cursor = 0 },
  }
}

/**
 * Capture the bundle factory ONCE, then invoke it per case so each one gets a
 * module bound to its own React stand-in.
 */
let capturedFactory
async function loadPanel(data) {
  if (capturedFactory === undefined) {
    globalThis.window = {
      __ModuleLoader__: {
        load: ({ id, factory }) => {
          assert.equal(id, 'dsh-plugin-sql-security-validate')
          capturedFactory = factory
        },
      },
    }
    globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => data })
    await import(new URL('../src/client.js', import.meta.url).href)
  }
  globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => data })

  const react = makeReact([{ status: 'ready', data, error: '' }, null, null, ''])
  const mod = capturedFactory((name) => {
    if (name === 'react') return react
    throw new Error(`unexpected require: ${name}`)
  })
  const registrations = []
  const ctx = {
    configForms: {
      get: () => ({
        getSnapshot: () => ({ status: 'ready', value: {}, revision: 0 }),
        set: async () => true,
        subscribe: () => () => {},
      }),
    },
    slots: {
      inject: (name, register) => { register() },
      register: (options, Component) => { registrations.push({ options, Component }) },
    },
  }
  mod.apply(ctx)
  const section = registrations.find(entry => entry.options.name === 'settings.section')
  const turnCard = registrations.find(entry => entry.options.name === 'conversation.chat.turnTail')
  assert.ok(section !== undefined, 'settings section registered')
  assert.ok(turnCard !== undefined, 'turn-tail card registered')
  return { react, registration: section, turnCard }
}

/** Render the settings section and return its concatenated text. */
function renderPanel(react, registration) {
  const props = {
    configForm: { set: async () => true },
    ...(registration.options.inject ? registration.options.inject() : {}),
  }
  react.reset()
  return react.render(react.createElement(registration.Component, props))
}

/**
 * Render the per-turn card and return its text plus the element list.
 *
 * The card's hook order is `useState(open)`, `useState(data)`,
 * `useState(error)`, then `useCallback(load)` — so the seed array is exactly
 * `[open, payload, '']`. The SAME React instance `loadPanel` handed the module
 * must be reused: a fresh stub would carry its own state table while the
 * component closure still reads the original one.
 *
 * @param {object} react the stub bound to this case's module.
 * @param {object} turnCard the registered card.
 * @param {number} turn turn number the slot owner supplies.
 * @param {object} payload what the Host returns for `?turn=N`.
 * @param {boolean} open whether the card starts expanded.
 */
function renderTurnCard(react, turnCard, turn, payload, open = false) {
  const originalFetch = globalThis.fetch
  globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => payload })
  const captured = []
  const nodes = []
  const walk = (node) => {
    if (node === null || node === undefined) return
    if (Array.isArray(node)) { node.forEach(walk); return }
    if (typeof node === 'string' || typeof node === 'number') { captured.push(String(node)); return }
    if (typeof node !== 'object') return
    if (typeof node.fn === 'function') {
      // A child component starts its own hook cursor; the parent's state was
      // already read before this point.
      react.reset()
      walk(node.fn({ ...node.props, children: undefined }))
      return
    }
    nodes.push(node)
    if (node.props) walk(node.props.children)
  }
  try {
    react.seed([open, payload, ''])
    react.reset()
    // The real slot hands over a TurnLocation object, not a bare number — the
    // shape that made the card render nothing in the browser. Mirror it here so
    // this test can never pass while the browser shows an empty slot.
    walk(turnCard.Component({
      turn: { turn, status: 'closed', steps: [], start: undefined, end: undefined },
      seq: 1,
      openFile: () => {},
    }))
    return { text: captured.join(''), nodes }
  } finally {
    globalThis.fetch = originalFetch
  }
}

const base = {
  enabled: true,
  auditEnable: true,
  securityMode: 'blacklist',
  strictGuard: false,
  antiUnmount: false,
  targetPrefixes: ['mcp__'],
  policy: { tables: [], columns: [], grantedTables: [], grantedColumns: [], remoteEnabled: false },
  records: [],
  total: 0,
}

/** One audit record, for the card and panel cases. */
const denyRecord = {
  seq: 1, time: 1792895431939, turn: 3, outcome: 'deny',
  forbiddenTables: ['admin'], forbiddenColumns: [], matchedRules: ['db.admin'],
  inspectedTables: ['admin'], statements: ['select'], sql: 'SELECT * FROM `admin`',
  policySource: 'local', interceptMode: 'pre-execute', sessionId: 's1',
}

const cases = []
const check = (label, fn) => cases.push({ label, fn })

// ── registrations ──────────────────────────────────────────────────────────
check('panel registers under settings.section with a label', async () => {
  const { registration } = await loadPanel(base)
  assert.equal(registration.options.name, 'settings.section')
  assert.equal(registration.options.id, 'sql-security-validate')
  assert.equal(registration.options.label(), 'SQL 权限校验')
})

check('a turn-tail card is registered under the conversation turn slot', async () => {
  const { turnCard } = await loadPanel(base)
  assert.equal(turnCard.options.name, 'conversation.chat.turnTail')
  assert.equal(turnCard.options.id, 'sql-security-turn')
  assert.equal(turnCard.options.label(), 'SQL 权限校验')
})

// ── the per-turn card ──────────────────────────────────────────────────────
check('the card reads the turn number out of a TurnLocation object', async () => {
  // Regression: the slot passes `{ turn: { turn: N, ... } }`, and accepting only
  // a bare number made every card render nothing in the browser.
  const data = { ...base, records: [denyRecord], total: 1 }
  const { react, turnCard } = await loadPanel(data)
  const originalFetch = globalThis.fetch
  let requested = ''
  globalThis.fetch = async (url) => {
    requested = String(url)
    return { ok: true, status: 200, json: async () => data }
  }
  try {
    react.seed([false, data, ''])
    react.reset()
    react.pendingEffects.length = 0
    turnCard.Component({
      turn: { turn: 42, status: 'closed', steps: [] },
      seq: 1,
      openFile: () => {},
    })
    // The component loads inside an effect; the stub records it instead of
    // running it, so drive it here to observe the request the card makes.
    for (const effect of react.pendingEffects) effect()
    assert.ok(requested.includes('turn=42'),
      `expected the query to carry turn=42, got: ${requested}`)
  } finally {
    globalThis.fetch = originalFetch
  }
})

check('a bare numeric turn still works', async () => {
  const data = { ...base, records: [denyRecord], total: 1 }
  const { react, turnCard } = await loadPanel(data)
  const originalFetch = globalThis.fetch
  let requested = ''
  globalThis.fetch = async (url) => {
    requested = String(url)
    return { ok: true, status: 200, json: async () => data }
  }
  try {
    react.seed([false, data, ''])
    react.reset()
    react.pendingEffects.length = 0
    turnCard.Component({ turn: 7, seq: 1, openFile: () => {} })
    for (const effect of react.pendingEffects) effect()
    assert.ok(requested.includes('turn=7'), `expected turn=7, got: ${requested}`)
  } finally {
    globalThis.fetch = originalFetch
  }
})

check('a turn with no interception contributes no DOM at all', async () => {
  const { react, turnCard } = await loadPanel(base)
  const { nodes } = renderTurnCard(react, turnCard, 3, { ...base, records: [], total: 0 })
  assert.equal(nodes.length, 0, 'nothing renders when the turn had no SQL activity')
})

check('a turn with a denial collapses to a one-line summary', async () => {
  const data = { ...base, records: [denyRecord], total: 1 }
  const { react, turnCard } = await loadPanel(data)
  const { text } = renderTurnCard(react, turnCard, 3, data)
  assert.ok(text.includes('本轮拦截 1 次 SQL'), `expected a summary, got: ${text.slice(0, 160)}`)
  assert.ok(text.includes('admin'), 'names the inspected table')
  assert.ok(!text.includes('SELECT * FROM'), 'the SQL stays collapsed until opened')
})

check('an all-allowed turn still reports that it ran', async () => {
  const allow = {
    seq: 1, time: 1, turn: 3, outcome: 'allow',
    forbiddenTables: [], forbiddenColumns: [], matchedRules: [],
    inspectedTables: ['user'], statements: ['select'], sql: 'SELECT id FROM user',
  }
  const data = { ...base, records: [allow], total: 1 }
  const { react, turnCard } = await loadPanel(data)
  const { text } = renderTurnCard(react, turnCard, 3, data)
  assert.ok(text.includes('全部放行'), `expected an allow summary, got: ${text.slice(0, 160)}`)
})

check('expanding a turn shows the SQL and the rule that matched', async () => {
  const data = { ...base, records: [denyRecord], total: 1 }
  const { react, turnCard } = await loadPanel(data)
  const { text } = renderTurnCard(react, turnCard, 3, data, true)
  assert.ok(text.includes('SELECT * FROM'), 'the SQL is visible when expanded')
  assert.ok(text.includes('db.admin'), 'the matched rule is visible')
  assert.ok(text.includes('收起'), 'the control offers to collapse again')
})

// ── settings panel: policy editors ─────────────────────────────────────────
check('empty blacklist renders an explanation with how to add a rule', async () => {
  const { react, registration } = await loadPanel(base)
  const text = renderPanel(react, registration)
  assert.ok(text.includes('还没有任何禁止条目'), `expected empty notice, got: ${text.slice(0, 160)}`)
  assert.ok(text.includes('未禁止的一律放行'), 'explains blacklist semantics')
  assert.ok(text.includes('db.table'), 'shows the entry format')
})

check('empty whitelist explains that everything is denied', async () => {
  const data = { ...base, securityMode: 'whitelist_emulate' }
  const { react, registration } = await loadPanel(data)
  const text = renderPanel(react, registration)
  assert.ok(text.includes('还没有任何放行条目'), `expected whitelist notice, got: ${text.slice(0, 160)}`)
  assert.ok(text.includes('未列出的一律禁止'), 'explains whitelist semantics')
  assert.ok(text.includes('不是故障'), 'reassures the user')
})

check('non-empty blacklist hides the empty notice and shows both editors', async () => {
  const data = { ...base, policy: { ...base.policy, tables: ['db.admin'], columns: ['db.user.phone'] } }
  const { react, registration } = await loadPanel(data)
  const text = renderPanel(react, registration)
  assert.ok(!text.includes('还没有任何禁止条目'))
  assert.ok(text.includes('禁止访问的表'))
  assert.ok(text.includes('禁止访问的字段'))
  assert.ok(text.includes('db.admin'), 'existing rule is shown in the editor')
})

check('whitelist mode shows the allow-list editors, not the blacklist ones', async () => {
  const data = {
    ...base,
    securityMode: 'whitelist_emulate',
    policy: { ...base.policy, grantedTables: ['demo.user'] },
  }
  const { react, registration } = await loadPanel(data)
  const text = renderPanel(react, registration)
  assert.ok(text.includes('允许访问的表'), 'whitelist editor present')
  assert.ok(!text.includes('禁止访问的表'), 'blacklist editor absent in whitelist mode')
  assert.ok(text.includes('不需要权限中台'), 'states the local-only capability')
})

check('remote policy enabled is called out', async () => {
  const data = { ...base, policy: { ...base.policy, tables: ['db.admin'], remoteEnabled: true } }
  const { react, registration } = await loadPanel(data)
  const text = renderPanel(react, registration)
  assert.ok(text.includes('已开启远程权限中台'))
})

check('the settings panel still lists records and matched rules', async () => {
  const data = { ...base, policy: { ...base.policy, tables: ['db.admin'] }, records: [denyRecord], total: 1 }
  const { react, registration } = await loadPanel(data)
  const text = renderPanel(react, registration)
  assert.ok(text.includes('最近 1 条'), 'counts the record')
  assert.ok(text.includes('拒绝'), 'shows the outcome')
  assert.ok(text.includes('admin'), 'shows the refused resource')
})

check('missing config form degrades to read-only instead of throwing', async () => {
  const { react, registration } = await loadPanel(base)
  react.reset()
  const text = react.render(react.createElement(registration.Component, {}))
  assert.ok(text.includes('没有配置写入通道'), 'explains the degraded state')
  assert.ok(!text.includes('禁止访问的表'), 'no editors without a write channel')
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
