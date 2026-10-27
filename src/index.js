/**
 * dsh-plugin-sql-security-validate — AI SQL 权限校验拦截插件（宿主半边）。
 *
 * ## 这个插件做什么
 *
 * 拦截智能体（Agent）通过数据库 MCP 工具发起的每一次 SQL 调用，对 SQL 做完整
 * 资源解析（表、字段、JOIN、子查询、函数），合并本地静态黑名单与远程权限中台
 * 策略，越权则**直接拒绝执行**，并把结构化拒绝原因返回给模型——让模型自主剔除
 * 越权字段重写 SQL、更换统计口径，或用自然语言告知用户权限不足。
 *
 * ## 三条不可协商的原则
 *
 * 1. **永不静默改写 SQL。** 拒绝是显式的，原因是可读的。静默删字段会让模型以为
 *    数据完整，从而产生幻觉答案。
 * 2. **默认极致通用、可卸载。** 所有安全强锁定能力默认关闭：不防卸载、不强依赖
 *    校验、不启用严格守卫。普通用户装一个问数闸门，卸载零代价。
 * 3. **安全能力按需加固。** 企业生产环境打开 `enableStrictGuardMode`，拒绝决策
 *    即进入 DSH 最高安全级别 `ctx.tools.guard()`——单调、不可被任何后置插件推翻，
 *    彻底封堵多插件事件覆盖这条唯一的插件层绕过路径。
 *
 * ## 为什么 Agent 无法从底层绕过
 *
 * 大模型 Agent 没有网络能力、没有协议权限，无法直连 MCP 服务。它只能输出 DSH
 * 规范的工具调用 JSON，所有 MCP 请求必须经过 DSH Runtime 调度流水线：
 * `Agent 输出工具调用 → 本插件拦截层 → MCP 真实执行`。
 *
 * ## 双引擎
 *
 * - `tools/pre-execute`（默认）：兼容性最强的普通事件拦截，可以 await 远程策略。
 * - `ctx.tools.guard()`（可选）：单调守卫，同步、拒绝后不可推翻。守卫需要同步
 *   判定，因此只使用已缓存的远程策略；缓存尚未就绪时 fail-closed。
 *
 * @module dsh-plugin-sql-security-validate
 */

import z from '@deepseek-ai/schemastery'
import { collectSqlCandidates } from './sql-parse.js'
import { Policy, RemotePolicyClient, mergePolicy } from './policy.js'
import { AuditLog, defaultAuditPath } from './audit.js'

/** Cordis 插件名，用于 loader 诊断。 */
export const name = 'sql-security-validate'

/** 必需服务；缺一个时插件保持不激活而不是抛错。 */
export const inject = ['tools']

/** 默认目标工具名前缀：MCP 桥接的工具名恒为 `mcp__<server>__<tool>`。 */
const DEFAULT_TOOL_PREFIXES = ['mcp__']

/** 设置页读取审计数据的只读路由（宿主侧注册，客户端同源 fetch）。 */
const AUDIT_ROUTE = '/plugins/dsh-plugin-sql-security-validate/audit'

/** 默认被视为 SQL 的参数键。 */
const DEFAULT_SQL_KEYS = ['sql', 'query', 'statement', 'text', 'command']

/** 拒绝原因主句；模型与用户看到的第一句。 */
const DENY_MESSAGE = '当前SQL包含无权限访问的资源，已禁止执行'

/**
 * Execution tokens already written to the audit log.
 *
 * A call passes through both engines when strict mode is on, and the same call
 * must produce exactly one audit record. Tokens are the registry's per-call
 * identity, so they de-duplicate without colliding across calls. Bounded: an
 * entry is dropped once the set is large, and only in-flight calls can collide.
 */
const RECORDED = new Set()

/** 稳定错误码，随结构化拒绝一起返回。 */
const DENY_CODE = 'SQL_PERMISSION_DENIED'

/** 远程中台不可用时的拒绝原因。 */
const REMOTE_UNAVAILABLE = 'SQL 权限校验失败：远程权限中台不可用，已按安全优先策略拒绝执行'

/** 严格守卫在策略缓存未就绪时的拒绝原因。 */
const GUARD_NOT_READY = 'SQL 权限校验失败：远程权限中台策略尚未就绪，已按安全优先策略拒绝执行'

/**
 * 插件配置。5.1/5.2 与文档一一对应，其余为落地所需的接线项，全部有默认值。
 *
 * 只有叶子字段标 `volatile()`：schemastery 不允许在 volatile 对象内部再嵌套
 * volatile 字段，而设置页只需要能就地改值、不必重挂插件。
 */
export const Config = z.object({
  enable: z.boolean().default(true).volatile(),
  auditEnable: z.boolean().default(true).volatile(),
  securityMode: z.union(['blacklist', 'whitelist_emulate']).default('blacklist').volatile(),
  enableStrictGuardMode: z.boolean().default(false).volatile(),
  enableAntiUnmount: z.boolean().default(false).volatile(),
  enableBundleRequireLock: z.boolean().default(false).volatile(),
  requiredBundles: z.array(z.string()).default([]).volatile(),
  sqlParamKeys: z.array(z.string()).default(DEFAULT_SQL_KEYS).volatile(),
  targetToolPrefixes: z.array(z.string()).default(DEFAULT_TOOL_PREFIXES).volatile(),
  includeNonMcpSqlTools: z.boolean().default(false).volatile(),
  localBlacklist: z.object({
    tables: z.array(z.string()).default([]),
    columns: z.array(z.string()).default([]),
  }).default({ tables: [], columns: [] }).volatile(),
  /**
   * Locally configured whitelist grants, so `whitelist_emulate` works without a
   * policy center. A generic deployment often wants "only these tables" with no
   * central service at all; requiring one would make the mode unusable there.
   */
  localWhitelist: z.object({
    tables: z.array(z.string()).default([]),
    columns: z.array(z.string()).default([]),
  }).default({ tables: [], columns: [] }).volatile(),
  /**
   * Whether table-less schema discovery (`SHOW TABLES`, `SHOW DATABASES`) is
   * allowed.
   *
   * An AI that cannot enumerate tables cannot write a query, so discovery is on
   * by default. A deployment that treats table *names* as confidential turns it
   * off; DESCRIBE / SHOW CREATE remain governed per-table either way.
   */
  allowSchemaDiscovery: z.boolean().default(true).volatile(),
  /**
   * Whether a whitelist grant written as a bare table name may reach a
   * qualified resource.
   *
   * Off (default) keeps the documented tolerance: `grant=user` admits both
   * `FROM user` and `FROM demo.user`. It also admits `FROM mysql.user`, because
   * a bare entry aligns against the resource's tail — harmless when the
   * operator meant one database, dangerous when several databases share a table
   * name.
   *
   * On restricts a bare grant to bare references. Qualified grants
   * (`demo.user`) behave identically either way and are the recommended form.
   */
  strictDatabaseQualification: z.boolean().default(false).volatile(),
  /**
   * Whether a statement the parser cannot interpret is refused.
   *
   * Off by default: MySQL accepts many legacy forms the parser rejects, and
   * refusing them all would break working queries. Turn it on where the
   * parser's grammar is known to cover everything the deployment sends.
   */
  failOnParseError: z.boolean().default(false).volatile(),
  remotePolicy: z.object({
    enabled: z.boolean().default(false),
    policyApiUrl: z.string().default(''),
    policyApiToken: z.string().role('secret').default(''),
    apiTimeoutMs: z.number().step(1).min(1).default(3000),
    cacheTtlMs: z.number().step(1).min(0).default(30000),
    tenantId: z.string().default(''),
    userId: z.string().default(''),
  }).default({
    enabled: false,
    policyApiUrl: '',
    policyApiToken: '',
    apiTimeoutMs: 3000,
    cacheTtlMs: 30000,
    tenantId: '',
    userId: '',
  }).volatile(),
  audit: z.object({
    maxRecords: z.number().step(1).min(1).default(5000),
    redactSql: z.boolean().default(false),
    logPath: z.string().default(''),
  }).default({ maxRecords: 5000, redactSql: false, logPath: '' }).volatile(),
})

/**
 * Read one config field, tolerating both shapes the Loader can hand a plugin:
 * a live `volatile()` reference (`.get()`) and a plain value, which is what a
 * row that supplies its own `config` in `cordis.patch.yml` yields.
 * @param field the config field value.
 * @param fallback value used when the field is absent.
 * @returns the field's current value.
 */
function readField(field, fallback) {
  if (field === undefined || field === null) return fallback
  if (typeof field.get === 'function') {
    const value = field.get()
    return value === undefined ? fallback : value
  }
  return field
}

/**
 * Read one nested config group, normalising each of its fields.
 * @param group the config group value.
 * @param defaults the group's default values.
 * @returns a plain object of current values.
 */
function readGroup(group, defaults) {
  const source = readField(group, defaults)
  const out = {}
  for (const [key, fallback] of Object.entries(defaults)) {
    out[key] = readField(source?.[key], fallback)
  }
  return out
}

/** Default values of the nested config groups, kept in one place. */
const GROUP_DEFAULTS = {
  localBlacklist: { tables: [], columns: [] },
  localWhitelist: { tables: [], columns: [] },
  remotePolicy: {
    enabled: false,
    policyApiUrl: '',
    policyApiToken: '',
    apiTimeoutMs: 3000,
    cacheTtlMs: 30000,
    tenantId: '',
    userId: '',
  },
  audit: { maxRecords: 5000, redactSql: false, logPath: '' },
}

/**
 * 读取当前配置快照。volatile 字段 `.get()` 取即时值，普通字段直接读，
 * 两种形态都支持，因此改配置即时生效。
 * @param config 已校验配置。
 * @returns 普通 JSON 形状的当前配置。
 */
export function snapshotOf(config) {
  return {
    enable: readField(config.enable, true),
    auditEnable: readField(config.auditEnable, true),
    securityMode: readField(config.securityMode, 'blacklist'),
    enableStrictGuardMode: readField(config.enableStrictGuardMode, false),
    enableAntiUnmount: readField(config.enableAntiUnmount, false),
    enableBundleRequireLock: readField(config.enableBundleRequireLock, false),
    requiredBundles: [...readField(config.requiredBundles, [])],
    sqlParamKeys: [...readField(config.sqlParamKeys, DEFAULT_SQL_KEYS)],
    targetToolPrefixes: [...readField(config.targetToolPrefixes, DEFAULT_TOOL_PREFIXES)],
    includeNonMcpSqlTools: readField(config.includeNonMcpSqlTools, false),
    allowSchemaDiscovery: readField(config.allowSchemaDiscovery, true),
    strictDatabaseQualification: readField(config.strictDatabaseQualification, false),
    failOnParseError: readField(config.failOnParseError, false),
    localBlacklist: readGroup(config.localBlacklist, GROUP_DEFAULTS.localBlacklist),
    localWhitelist: readGroup(config.localWhitelist, GROUP_DEFAULTS.localWhitelist),
    remotePolicy: readGroup(config.remotePolicy, GROUP_DEFAULTS.remotePolicy),
    audit: readGroup(config.audit, GROUP_DEFAULTS.audit),
  }
}

/**
 * 判断一次工具调用是否在本插件的管辖范围内。
 * @param toolName 工具名。
 * @param settings 当前配置快照。
 * @returns true 表示需要做 SQL 权限校验。
 */
function targets(toolName, settings) {
  const prefixes = settings.targetToolPrefixes.length > 0 ? settings.targetToolPrefixes : DEFAULT_TOOL_PREFIXES
  if (prefixes.some(prefix => prefix !== '' && toolName.startsWith(prefix))) return true
  return settings.includeNonMcpSqlTools === true
}

/**
 * 组装交给 {@link mergePolicy} 的本地策略：黑名单 + 本地白名单授权。
 * 白名单模式因此不依赖权限中台，面板里配好条目即可生效。
 * @param settings 当前配置快照。
 * @returns 含 forbidden* 与 granted* 的本地策略输入。
 */
function localPolicyInput(settings) {
  const blacklist = settings.localBlacklist ?? { tables: [], columns: [] }
  const whitelist = settings.localWhitelist ?? { tables: [], columns: [] }
  return {
    tables: blacklist.tables ?? [],
    columns: blacklist.columns ?? [],
    grantedTables: whitelist.tables ?? [],
    grantedColumns: whitelist.columns ?? [],
  }
}

/**
 * Read the optional `?turn=<n>` filter from a request URL.
 * @param req incoming request.
 * @returns the turn number, or undefined when absent or malformed.
 */
function readTurnQuery(req) {
  const url = typeof req?.url === 'string' ? req.url : ''
  const query = url.includes('?') ? url.slice(url.indexOf('?') + 1) : ''
  if (query === '') return undefined
  for (const pair of query.split('&')) {
    const [key, raw] = pair.split('=')
    if (key !== 'turn' || raw === undefined) continue
    const turn = Number(decodeURIComponent(raw))
    return Number.isInteger(turn) && turn >= 0 ? turn : undefined
  }
  return undefined
}

/**
 * 取当前所处的轮次号，供审计记录按轮归组。
 *
 * 直接用 agent-loop 已注册的 `turnBoundary` 投影：它由宿主在每次 turn/start、
 * turn/end 时折叠维护，是「当前第几轮」的权威来源。自己扫会话事件既慢又容易
 * 在压缩、分叉的会话上取错。
 *
 * 没有 sessionProjections（精简部署）时退回事件扫描；两者都不可用时返回 -1，
 * 客户端会按会话聚合而不是按轮。
 *
 * @param ctx 插件上下文，用于取可选的 sessionProjections。
 * @param agent 发起调用的 Agent，可能缺失。
 * @returns 轮次号，未知为 -1。
 */
function currentTurn(ctx, agent) {
  const session = agent?.session
  if (session === undefined) return -1

  // Preferred: the host's own turn-boundary projection.
  const projections = ctx.get('sessionProjections')
  if (projections !== undefined && typeof projections.stateOf === 'function') {
    try {
      const state = projections.stateOf(session, 'turnBoundary')
      if (state !== undefined && typeof state.lastTurn === 'number') return state.lastTurn
    } catch {
      // Fall through to the event scan.
    }
  }

  // Fallback: read the tail of the log for the most recent turn boundary.
  if (typeof session.snapshotEvents !== 'function') return -1
  try {
    const events = session.snapshotEvents()
    for (let index = events.length - 1; index >= 0 && index >= events.length - 200; index -= 1) {
      const event = events[index]
      if (event?.type === 'turn/start' && typeof event.data?.turn === 'number') return event.data.turn
    }
    return -1
  } catch {
    return -1
  }
}

/** 一次调用的校验上下文。 */
class Evaluation {
  /**
   * @param options 执行上下文、配置快照、远程客户端、审计日志与日志器。
   */
  constructor(options) {
    this.exec = options.exec
    this.settings = options.settings
    this.remote = options.remote
    this.audit = options.audit
    this.logger = options.logger
    /** Plugin context, used for the optional session-projections lookup. */
    this.ctx = options.ctx
  }

  /**
   * 合并本地与远程策略。远程启用但不可用时抛出，由调用方 fail-closed。
   * @returns 可直接决策的 Policy。
   */
  async buildPolicy() {
    const local = localPolicyInput(this.settings)
    const remoteConfig = this.settings.remotePolicy ?? {}
    if (remoteConfig.enabled === true && this.remote.configured) {
      const fetched = await this.remote.read()
      return new Policy({
      securityMode: this.settings.securityMode,
      strictDatabaseQualification: this.settings.strictDatabaseQualification === true,
      ...mergePolicy(local, fetched),
    })
    }
    return new Policy({
      securityMode: this.settings.securityMode,
      strictDatabaseQualification: this.settings.strictDatabaseQualification === true,
      ...mergePolicy(local, undefined),
    })
  }

  /**
   * 对全部候选 SQL 做一次汇总判定。
   * @param policy 已合并的策略。
   * @returns 汇总后的越权资源清单、命中规则与被检查过的对象。
   */
  verdict(policy) {
    const candidates = collectSqlCandidates(this.exec.arguments, {
      keys: this.settings.sqlParamKeys,
      includeOthers: this.settings.includeNonMcpSqlTools,
    })
    const forbiddenTables = []
    const forbiddenColumns = []
    const matchedRules = []
    const inspectedTables = []
    const statements = []
    /** Discovery statements that name no table at all (`SHOW TABLES`). */
    let tablelessDiscovery = false
    /** A statement the parser could not interpret. */
    let unparseable = false
    for (const candidate of candidates) {
      const outcome = policy.decide(candidate.parsed)
      for (const table of outcome.forbiddenTables) if (!forbiddenTables.includes(table)) forbiddenTables.push(table)
      for (const column of outcome.forbiddenColumns) if (!forbiddenColumns.includes(column)) forbiddenColumns.push(column)
      for (const rule of outcome.matchedRules ?? []) if (!matchedRules.includes(rule)) matchedRules.push(rule)
      for (const table of candidate.parsed.tables) if (!inspectedTables.includes(table)) inspectedTables.push(table)
      for (const kind of candidate.parsed.statementKinds) if (!statements.includes(kind)) statements.push(kind)
      if (candidate.parsed.parseError === true) unparseable = true
      if (candidate.parsed.metadata === true && candidate.parsed.tables.length === 0) tablelessDiscovery = true
    }
    return {
      candidateCount: candidates.length,
      forbiddenTables,
      forbiddenColumns,
      matchedRules,
      inspectedTables,
      statements,
      tablelessDiscovery,
      unparseable,
    }
  }

  /**
   * 写一条审计记录（受 auditEnable 与 maxRecords 约束）。
   * @param verdict 判定结果。
   * @param interceptMode 本次经由哪个引擎。
   * @param policySource 策略来源。
   * @param reason 拒绝原因；放行时为空串。
   */
  record(verdict, interceptMode, policySource, reason) {
    if (this.audit === undefined || this.settings.auditEnable !== true) return
    // Both engines run for one call when strict mode is on: pre-execute decides,
    // then the guard re-checks. Recording in both would double-count every
    // query. De-duplicate on the registry-minted execution token, which is
    // stable per call and unique across them.
    const token = this.exec.token
    if (token !== undefined) {
      if (RECORDED.has(token)) return
      RECORDED.add(token)
      // Bound the set: tokens are per-call symbols, so entries would otherwise
      // accumulate for the life of the process.
      if (RECORDED.size > 4096) {
        const oldest = RECORDED.values().next().value
        RECORDED.delete(oldest)
      }
    }
    this.audit.append({
      sessionId: this.exec.agent?.session?.id ?? this.exec.agent?.id ?? '',
      // The turn lets the conversation's turn-tail card show only what THIS
      // turn touched; without it the client can only aggregate per session.
      turn: currentTurn(this.ctx, this.exec.agent),
      toolName: this.exec.name,
      callId: this.exec.callId,
      outcome: reason === '' ? 'allow' : 'deny',
      securityMode: this.settings.securityMode,
      interceptMode,
      policySource,
      reason,
      forbiddenTables: verdict.forbiddenTables,
      forbiddenColumns: verdict.forbiddenColumns,
      matchedRules: verdict.matchedRules ?? [],
      inspectedTables: verdict.inspectedTables ?? [],
      statements: verdict.statements ?? [],
      sql: firstSqlText(this.exec.arguments, this.settings),
    })
  }
}

/**
 * 取第一段 SQL 文本用于审计；不含任何改写。
 * @param args 工具参数。
 * @param settings 当前配置。
 * @returns 原始 SQL 或空串。
 */
function firstSqlText(args, settings) {
  const candidates = collectSqlCandidates(args, {
    keys: settings.sqlParamKeys,
    includeOthers: settings.includeNonMcpSqlTools,
  })
  return candidates.length > 0 ? candidates[0].sql : ''
}

/**
 * 把越权资源渲染成一句模型可读的原因，并附结构化明细。
 * @param tables 越权表。
 * @param columns 越权字段。
 * @param detail 其余结构字段。
 * @returns 模型可读的多行原因。
 */
function denyReason(tables, columns, detail) {
  const parts = []
  if (tables.length > 0) parts.push(`无权限访问的表 ${tables.join('、')}`)
  if (columns.length > 0) parts.push(`无权限访问的字段 ${columns.join('、')}`)
  const structured = JSON.stringify({
    success: false,
    code: DENY_CODE,
    message: DENY_MESSAGE,
    detail: {
      forbiddenTables: tables,
      forbiddenColumns: columns,
      securityMode: detail.securityMode,
      interceptMode: detail.interceptMode,
      policySource: detail.policySource,
    },
  })
  return `${DENY_MESSAGE}：${parts.join('；')}。请改用有权限的资源重新生成 SQL，或向用户说明权限不足。\n${structured}`
}

/**
 * 挂载两个拦截引擎。
 * @param ctx 插件上下文。
 * @param deps 远程客户端、审计日志、配置读取函数。
 * @returns 清理函数。
 */
function installEngines(ctx, deps) {
  const { remote, audit, snapshot, logger } = deps

  // 引擎一（默认）：普通事件拦截。兼容性最强，可 await 远程策略。
  const offPreExecute = ctx.on('tools/pre-execute', async (exec, next) => {
    const settings = snapshot()
    if (!settings.enable || !targets(exec.name, settings)) return next()
    const evaluation = new Evaluation({ exec, settings, remote, audit, logger, ctx })
    let policy
    try {
      policy = await evaluation.buildPolicy()
    } catch (error) {
      logger.warn('sql-security-validate: remote policy unavailable: %s', String(error?.message ?? error))
      evaluation.record({ forbiddenTables: [], forbiddenColumns: [] }, 'pre-execute', 'unavailable', REMOTE_UNAVAILABLE)
      return { kind: 'deny', reason: REMOTE_UNAVAILABLE, info: { name: 'SqlPermissionDenied', code: DENY_CODE } }
    }
    const verdict = evaluation.verdict(policy)
    if (verdict.candidateCount === 0) return next()

    // A pattern that never parses could hide arbitrary intent, so it is refused
    // rather than waved through — but only when the text does look like SQL.
    if (verdict.unparseable && settings.failOnParseError === true) {
      const reason = `${DENY_MESSAGE}：无法解析该语句，已按安全优先拒绝`
      evaluation.record(verdict, 'pre-execute', policy.policySource, reason)
      return { kind: 'deny', reason, info: { name: 'SqlPermissionDenied', code: 'SQL_UNPARSABLE' } }
    }
    // Table-less schema discovery (`SHOW TABLES`) is allowed or refused purely
    // by configuration: it names no resource for the policy to judge.
    if (verdict.tablelessDiscovery && settings.allowSchemaDiscovery !== true) {
      const reason = `${DENY_MESSAGE}：已关闭结构发现，SHOW 类语句被禁止`
      evaluation.record(verdict, 'pre-execute', policy.policySource, reason)
      return { kind: 'deny', reason, info: { name: 'SqlPermissionDenied', code: 'SQL_DISCOVERY_DISABLED' } }
    }
    if (verdict.forbiddenTables.length === 0 && verdict.forbiddenColumns.length === 0) {
      evaluation.record(verdict, 'pre-execute', policy.policySource, '')
      return next()
    }
    const reason = denyReason(verdict.forbiddenTables, verdict.forbiddenColumns, {
      securityMode: settings.securityMode,
      interceptMode: 'pre-execute',
      policySource: policy.policySource,
    })
    evaluation.record(verdict, 'pre-execute', policy.policySource, reason)
    logger.warn('sql-security-validate: refused %s (%s)', exec.name, policy.policySource)
    return { kind: 'deny', reason, info: { name: 'SqlPermissionDenied', code: DENY_CODE } }
  })

  // 引擎二（企业）：单调守卫严格拦截。注册永久生效，是否行动看当前配置，
  // 因此打开开关即时生效，关掉也即时恢复默认语义。
  const offGuard = ctx.tools.guard((exec) => {
    const settings = snapshot()
    if (!settings.enable || settings.enableStrictGuardMode !== true) return undefined
    if (!targets(exec.name, settings)) return undefined
    const evaluation = new Evaluation({ exec, settings, remote, audit, logger, ctx })
    const remoteConfig = settings.remotePolicy ?? {}
    if (remoteConfig.enabled === true && remote.configured && remote.snapshot === undefined) {
      evaluation.record({ forbiddenTables: [], forbiddenColumns: [] }, 'guard', 'unavailable', GUARD_NOT_READY)
      return GUARD_NOT_READY
    }
    const local = localPolicyInput(settings)
    const policy = new Policy({
      securityMode: settings.securityMode,
      strictDatabaseQualification: settings.strictDatabaseQualification === true,
      ...mergePolicy(local, remote.snapshot?.policy),
    })
    const verdict = evaluation.verdict(policy)
    if (verdict.candidateCount === 0) return undefined
    // Same two gates as the pre-execute engine: the guard re-checks the same
    // call, so it must reach the same conclusion.
    if (verdict.unparseable && settings.failOnParseError === true) {
      const reason = `${DENY_MESSAGE}：无法解析该语句，已按安全优先拒绝`
      evaluation.record(verdict, 'guard', policy.policySource, reason)
      return reason
    }
    if (verdict.tablelessDiscovery && settings.allowSchemaDiscovery !== true) {
      const reason = `${DENY_MESSAGE}：已关闭结构发现，SHOW 类语句被禁止`
      evaluation.record(verdict, 'guard', policy.policySource, reason)
      return reason
    }
    if (verdict.forbiddenTables.length === 0 && verdict.forbiddenColumns.length === 0) {
      evaluation.record(verdict, 'guard', policy.policySource, '')
      return undefined
    }
    const reason = denyReason(verdict.forbiddenTables, verdict.forbiddenColumns, {
      securityMode: settings.securityMode,
      interceptMode: 'guard',
      policySource: policy.policySource,
    })
    evaluation.record(verdict, 'guard', policy.policySource, reason)
    return reason
  })

  return () => {
    offPreExecute()
    offGuard()
  }
}

/**
 * 防卸载保护：把“拒绝卸载”表达为一条单调守卫。
 *
 * 本插件不改写 profile、不删除任何文件。当 `plugin_manager` 被用来停用或移除
 * 本插件、且 `enableAntiUnmount` 为真时，该操作被守卫拒绝，并写明如何合法解除。
 * 因此它是可解释、可撤销的硬化，而不是不可见的锁定；默认关闭时完全不存在。
 * @param ctx 插件上下文。
 * @param snapshot 配置读取函数。
 * @param ownerIds 本插件在 profile 里的行 id 与包名。
 * @returns 守卫卸载函数。
 */
function installAntiUnmount(ctx, snapshot, ownerIds) {
  return ctx.tools.guard((exec) => {
    if (exec.name !== 'plugin_manager') return undefined
    if (snapshot().enableAntiUnmount !== true) return undefined
    const args = exec.arguments
    if (args === null || typeof args !== 'object') return undefined
    const action = typeof args.action === 'string' ? args.action : ''
    if (action !== 'set_plugin' && action !== 'set_bundle' && action !== 'remove_bundle') return undefined
    // 只有“停用 / 移除”才是卸载动作；重新启用必须放行。
    if (args.enabled !== false && action !== 'remove_bundle') return undefined
    const target = typeof args.target === 'string' ? args.target : ''
    const owned = ownerIds.some(id => id !== '' && (target === id || target.startsWith(`${id}@`)))
    if (!owned) return undefined
    return '已开启防卸载保护：拒绝卸载/停用 AI SQL 权限校验拦截插件。'
      + '如需卸载，请先把该插件的 enableAntiUnmount 配置为 false。'
  })
}

/**
 * 强依赖校验：声明的必需 bundle 必须由本轮 activation 的 compose 提供。
 * 没有 `requiredBundles` 时不检查，因此默认不绑架任何部署。
 * @param snapshot 配置读取函数。
 * @param ctx 插件上下文。
 * @throws 当开启强依赖校验且列出的 bundle 缺失时。
 */
function assertRequiredBundles(snapshot, ctx) {
  const settings = snapshot()
  if (settings.enableBundleRequireLock !== true) return
  const required = (settings.requiredBundles ?? []).filter(item => typeof item === 'string' && item !== '')
  if (required.length === 0) return
  const started = ctx.root?.profileContext?.startedBundles
  if (!Array.isArray(started)) {
    throw new Error(
      `sql-security-validate: enableBundleRequireLock is on but the profile context is unavailable; cannot verify ${required.join(', ')}`,
    )
  }
  const missing = required.filter(bundle => !started.includes(bundle))
  if (missing.length === 0) return
  throw new Error(
    `sql-security-validate: enableBundleRequireLock is on and these required bundles are not selected: ${missing.join(', ')}`,
  )
}

/**
 * 挂载插件。
 * @param ctx 插件上下文。
 * @param config 已校验配置。
 */
export function apply(ctx, config) {
  const initial = snapshotOf(config)
  const logger = ctx.logger('sql-security-validate')
  const snapshot = () => snapshotOf(config)

  // 强依赖校验放在最前：声明了就必须真的存在，否则激活即失败。
  assertRequiredBundles(snapshot, ctx)

  const remote = new RemotePolicyClient(initial.remotePolicy)
  const audit = new AuditLog({
    maxRecords: initial.audit.maxRecords,
    redactSql: initial.audit.redactSql,
    path: initial.audit.logPath !== '' ? initial.audit.logPath : defaultAuditPath(),
  })
  audit.logger = logger
  void audit.hydrate()

  const disposeEngines = installEngines(ctx, { remote, audit, logger, snapshot })

  const ownerIds = ['sql-security-validate', 'dsh-plugin-sql-security-validate', '@local/dsh-plugin-sql-security-validate']
  const disposeAntiUnmount = initial.enableAntiUnmount === true
    ? installAntiUnmount(ctx, snapshot, ownerIds)
    : undefined

  ctx.effect(() => () => {
    disposeEngines()
    disposeAntiUnmount?.()
  }, 'sql-security-validate.engines')

  // 供配置页读取审计日志与当前策略快照。
  ctx.provide('sqlSecurityValidate', {
    snapshot: () => snapshotOf(config),
    listAudit: () => audit.list(),
    clearAudit: () => audit.clear(),
  })

  // Web 设置页的只读数据源。webServer 是可选依赖：桌面端或纯 CLI 下
  // 没有这个服务时回调不执行，宿主拦截逻辑不受影响。
  ctx.inject(['webServer'], (scoped) => {
    scoped.effect(() => scoped.webServer.register({
      kind: 'exact',
      path: AUDIT_ROUTE,
      handler: async (req, res) => {
        // DELETE clears the audit log; every other verb is a read.
        if (req.method === 'DELETE') {
          try {
            await audit.clear()
            res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' })
            res.end(JSON.stringify({ cleared: true }))
          } catch (error) {
            res.writeHead(500, { 'content-type': 'application/json; charset=utf-8' })
            res.end(JSON.stringify({ cleared: false, error: String(error?.message ?? error) }))
          }
          return
        }
        if (req.method !== 'GET') {
          res.writeHead(405, { allow: 'GET, DELETE' })
          res.end()
          return
        }
        const settings = snapshotOf(config)
        // `?turn=N` narrows the records to one conversation turn, which is what
        // the turn-tail card asks for; without it the panel shows everything.
        const requestedTurn = readTurnQuery(req)
        const all = audit.list()
        const records = (requestedTurn === undefined
          ? all
          : all.filter(record => record.turn === requestedTurn)).slice(0, 200)
        const body = JSON.stringify({
          enabled: settings.enable,
          auditEnable: settings.auditEnable,
          securityMode: settings.securityMode,
          strictGuard: settings.enableStrictGuardMode === true,
          antiUnmount: settings.enableAntiUnmount === true,
          targetPrefixes: settings.targetToolPrefixes ?? [],
          // The effective policy, so the panel can show what is enforced
          // rather than only what was hit.
          policy: {
            tables: settings.localBlacklist?.tables ?? [],
            columns: settings.localBlacklist?.columns ?? [],
            grantedTables: settings.localWhitelist?.tables ?? [],
            grantedColumns: settings.localWhitelist?.columns ?? [],
            remoteEnabled: settings.remotePolicy?.enabled === true,
          },
          records,
          total: all.length,
        })
        res.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store',
        })
        res.end(body)
      },
    }), 'sql-security-validate: audit route')
  })

  logger.info(
    'sql-security-validate: active (mode=%s, engine=%s, antiUnmount=%s, requireLock=%s)',
    initial.securityMode,
    initial.enableStrictGuardMode ? 'guard+pre-execute' : 'pre-execute',
    initial.enableAntiUnmount,
    initial.enableBundleRequireLock,
  )
}
