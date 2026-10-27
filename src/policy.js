/**
 * The permission policy engine: one resource set in, one decision out.
 *
 * Two modes, both driven by the same normalised resource set:
 *
 * - `blacklist` — an absent policy means allow; a hit on a local or remote
 *   blacklist means deny. The default for everyday AI 问数.
 * - `whitelist_emulate` — an absent grant means deny; only a resource the
 *   policy centre granted survives. No blacklist expansion, so no performance
 *   cliff on a large deployment.
 *
 * A remote fetch that fails is fail-closed: the call is refused rather than
 * silently downgraded, because guessing at permission is the one failure this
 * plugin exists to prevent. An empty remote answer keeps the local policy and
 * nothing else, which is the documented degradation.
 *
 * @module dsh-plugin-sql-security-validate/src/policy
 */

/** A merged view of every policy source for one decision. */
export class Policy {
  /**
   * @param options security mode, forbidden tables/columns, and granted sets.
   */
  constructor(options) {
    this.securityMode = options.securityMode === 'whitelist_emulate' ? 'whitelist_emulate' : 'blacklist'
    this.forbiddenTables = new Set(options.forbiddenTables ?? [])
    this.forbiddenColumns = new Set(options.forbiddenColumns ?? [])
    this.grantedTables = new Set(options.grantedTables ?? [])
    this.grantedColumns = new Set(options.grantedColumns ?? [])
    this.policySource = options.policySource ?? 'local'
    /**
     * Whether a grant written as a bare table name may reach a qualified
     * resource.
     *
     * Off keeps the historical tolerance: `grant=user` admits `demo.user` AND
     * `mysql.user`. On restricts a bare grant to bare references, so one entry
     * cannot open the same-named table in every database. Qualified grants
     * (`demo.user`) behave identically either way — this only governs the
     * ambiguous case where the operator never said which database they meant.
     */
    this.strictDatabaseQualification = options.strictDatabaseQualification === true
    /** `local` + `remote`, or `unavailable` when the remote fetch failed closed. */
    this.remoteState = options.remoteState ?? 'absent'
  }
  /**
   * Whether a resource string is covered by any entry in `entries`.
   *
   * Three matching rules, because a statement and a policy rarely agree on how
   * much of the name to write:
   *
   * 1. **Exact** — same dotted string.
   * 2. **Prefix** — `db.admin` governs `db.admin.col`, so one table entry also
   *    forbids its columns.
   * 3. **Suffix / placeholder** — `admin` matches `demo.admin`, and the
   *    documented default `db.admin` matches `demo.admin` too: in a multi-part
   *    entry the leading `db` segment is the documentation's placeholder for
   *    "whatever database", so it matches any first segment. Dropping or adding
   *    the schema qualifier therefore cannot dodge a policy.
   *
   * `*` is accepted as a whole-segment wildcard in any position.
   *
   * @param resource the parsed resource, e.g. `admin` or `demo.admin`.
   * @param entries policy entries.
   * @returns whether the resource is covered.
   */
  static coveredBy(resource, entries) {
    const actual = resource.split('.')
    for (const entry of Policy.listOf(entries)) {
      if (entry === resource) return true
      // A `db.table` entry also governs a `db.table.column` resource.
      if (resource.startsWith(`${entry}.`)) return true
      const pattern = entry.split('.')
      if (Policy.patternMatches(pattern, actual)) return true
    }
    return false
  }

  /**
   * Match one dotted policy entry against one dotted resource.
   *
   * The entry is aligned at every offset of the resource, so `admin` covers
   * `demo.admin`. The leading `db` of a multi-segment entry is the
   * documentation's placeholder for "any database": it matches any segment,
   * and — when the resource is bare (`admin`) — it matches nothing from the
   * resource at all, letting the remaining segments line up with the resource's
   * tail. That is what keeps the documented default `db.admin` effective
   * against `FROM admin`.
   *
   * ## Two tolerances, and why both need a guard
   *
   * Suffix tolerance lets a qualified entry admit a bare resource
   * (`demo.user` ← `FROM user`): an unqualified name carries no database to
   * compare, so refusing it would break every ordinary query.
   *
   * That tolerance reverses badly when the ENTRY is the bare one:
   * `grant=user` versus `resource=mysql.user` lines `user` up against the
   * resource's tail and grants a table in a database the operator never
   * authorised. The same shape appears on the forbidden side (`admin` covering
   * `demo.admin`, which IS wanted there). So the direction of specificity
   * decides whether the alignment is sound:
   *
   * - **Enforcement** (forbidden / deny): a bare entry must still catch a
   *   qualified resource, otherwise `admin` would stop blocking `demo.admin`.
   * - **Grant** (whitelist): a bare entry must NOT reach a qualified resource
   *   under `strictDatabaseQualification`, or a single `user` grant opens every
   *   database's `user` table.
   *
   * @param pattern entry segments.
   * @param actual resource segments.
   * @param options.grantSide true when matching a grant, which may not reach
   *   across databases; false for enforcement, which must.
   * @param options.strict true to reject a bare entry reaching a qualified
   *   resource on the grant side.
   * @returns whether the entry covers the resource.
   */
  static patternMatches(pattern, actual, options = {}) {
    if (pattern.length === 0 || actual.length === 0) return false
    const placeholder = pattern.length > 1 && pattern[0].toLowerCase() === 'db'
    const tail = placeholder ? pattern.slice(1) : pattern

    // A grant/denial may be MORE specific than the statement: `demo.user` must
    // admit a bare `FROM user`, because an unqualified table name carries no
    // database to compare against. That tolerance is only sound when the
    // resource itself is unqualified. When the resource DOES name a database,
    // `demo.user` must never match `mysql.user` — trimming the entry's leading
    // segment there would authorise a different database's same-named table.
    const resourceQualified = actual.length >= 2

    // The reverse direction: a bare GRANT must not reach a qualified resource.
    // `grant=user` would otherwise line up against the tail of `mysql.user` and
    // grant a table in a database the operator never authorised.
    const entryBare = tail.length === 1
    if (options.grantSide === true && options.strict === true && entryBare && resourceQualified) {
      return false
    }

    for (let trim = 0; trim < tail.length; trim += 1) {
      if (resourceQualified && trim > 0) break
      const candidate = tail.slice(trim)
      if (candidate.length === 0 || candidate.length > actual.length) continue
      for (let start = 0; start + candidate.length <= actual.length; start += 1) {
        let matched = true
        for (let index = 0; index < candidate.length; index += 1) {
          const want = candidate[index].toLowerCase()
          if (want !== '*' && want !== actual[start + index].toLowerCase()) { matched = false; break }
        }
        if (matched) return true
      }
    }
    return false
  }

  /**
   * Whether a granted resource string is covered by a grant entry.
   *
   * @param resource the parsed resource, e.g. `user` or `mysql.user`.
   * @param grants grant entries.
   * @param strict when true, a bare grant (`user`) does not reach a qualified
   *   resource (`mysql.user`), so one entry cannot open every database's
   *   same-named table. Defaults to false to preserve the documented tolerance.
   * @returns whether the resource is granted.
   */
  static grantedBy(resource, grants, strict = false) {
    for (const grant of Policy.listOf(grants)) {
      if (grant === resource) return true
      // A table grant `db.table` admits its columns and a wildcard suffix.
      if (resource.startsWith(`${grant}.`)) return true
      if (grant.endsWith('.*') && resource.startsWith(grant.slice(0, -1))) return true
      if (grant === '*') return true
      // Same suffix/placeholder tolerance as the forbidden side, except that a
      // bare grant must not cross into another database under `strict`.
      if (Policy.patternMatches(grant.split('.'), resource.split('.'), { grantSide: true, strict })) return true
    }
    return false
  }

  /**
   * Normalise a policy entry collection (Set or array) to an iterable array.
   * @param entries policy entries.
   * @returns plain array of entries.
   */
  static listOf(entries) {
    if (entries === undefined || entries === null) return []
    return entries instanceof Set ? [...entries] : entries
  }

  /**
   * Decide one parsed SQL statement.
   * @param parsed result of {@link parseSql}.
   * @returns outcome plus the exact refused resources and the policy entries
   *   that matched, never a rewritten SQL.
   */
  decide(parsed) {
    if (this.securityMode === 'whitelist_emulate') {
      const tables = parsed.tables.filter(table => !Policy.grantedBy(
        table, this.grantedTables, this.strictDatabaseQualification,
      ))
      const columns = parsed.columns.filter(column => !Policy.columnGranted(
        column, parsed.tables, this.grantedColumns, this.grantedTables, this.strictDatabaseQualification,
      ))
      return {
        allowed: tables.length === 0 && columns.length === 0,
        forbiddenTables: tables,
        forbiddenColumns: columns,
        // In whitelist mode a denial is "no grant matched", which is the rule.
        matchedRules: [...tables, ...columns].map(resource => `缺少授权：${resource}`),
        policySource: this.policySource,
      }
    }
    const tables = parsed.tables.filter(table => Policy.coveredBy(table, this.forbiddenTables))
    const columns = parsed.columns.filter(column => Policy.columnCovered(column, parsed.tables, this.forbiddenColumns))
    /** The concrete entries that fired, distinct from the resources they refused. */
    const matchedRules = []
    for (const table of tables) {
      for (const entry of Policy.listOf(this.forbiddenTables)) {
        if (Policy.coveredBy(table, [entry]) && !matchedRules.includes(entry)) matchedRules.push(entry)
      }
    }
    for (const column of columns) {
      for (const entry of Policy.listOf(this.forbiddenColumns)) {
        if (Policy.columnCovered(column, parsed.tables, [entry]) && !matchedRules.includes(entry)) matchedRules.push(entry)
      }
    }
    return {
      allowed: tables.length === 0 && columns.length === 0,
      forbiddenTables: tables,
      forbiddenColumns: columns,
      matchedRules,
      policySource: this.policySource,
    }
  }

  /**
   * Whether a column reference is forbidden. A bare column (`phone`) is matched
   * against every table the statement reads, so a policy entry of
   * `db.user.phone` still governs `SELECT phone FROM db.user`, and a two-part
   * entry (`user.phone`) governs the same reference.
   * @param column the column reference as written.
   * @param statementTables tables the statement reads.
   * @param entries forbidden column entries.
   * @returns whether the column is forbidden.
   */
  static columnCovered(column, statementTables, entries) {
    const list = Policy.listOf(entries)
    if (Policy.coveredBy(column, list)) return true
    const qualified = column.includes('.')
    const leaf = qualified ? column.slice(column.lastIndexOf('.') + 1) : column
    // A whole table entry (`db.user`) forbids every column of that table.
    if (qualified && statementTables.some(table => Policy.coveredBy(table, list))) return true
    for (const entry of list) {
      if (entry === column) return true
      if (entry.endsWith(`.${leaf}`)) return true
      if (statementTables.some(table => entry === `${table}.${leaf}`)) return true
    }
    return false
  }

  /**
   * Whether a column reference is granted, by the same widening rule as
   * {@link Policy.columnCovered}: a granted table grants its columns, and a
   * granted column entry matches by leaf name.
   * @param column the column reference as written.
   * @param statementTables tables the statement reads.
   * @param grants granted column entries.
   * @param tableGrants granted table entries.
   * @param strict when true, a bare grant does not reach a qualified resource.
   * @returns whether the column is granted.
   */
  static columnGranted(column, statementTables, grants, tableGrants = [], strict = false) {
    const grantedColumns = grants instanceof Set ? [...grants] : grants
    const grantedTableList = tableGrants instanceof Set ? [...tableGrants] : tableGrants
    if (Policy.grantedBy(column, grantedColumns, strict)) return true
    if (statementTables.some(table => Policy.grantedBy(table, grantedTableList, strict))) return true
    const leaf = column.includes('.') ? column.slice(column.lastIndexOf('.') + 1) : column
    return grantedColumns.some(entry => entry === leaf || entry.endsWith(`.${leaf}`))
  }
}

/** Cached remote policy snapshot plus when it was fetched. */
class RemoteSnapshot {
  /**
   * @param policy the fetched policy.
   * @param fetchedAt epoch milliseconds of the successful fetch.
   */
  constructor(policy, fetchedAt) {
    this.policy = policy
    this.fetchedAt = fetchedAt
  }

  /** Whether this snapshot still serves reads at `now`. */
  fresh(now, ttlMs) {
    return now - this.fetchedAt < ttlMs
  }
}

/**
 * Remote policy client over the documented standard OpenAPI.
 *
 * Request: `GET {policyApiUrl}` with `Authorization: Bearer {token}` and the
 * `tenantId` / `userId` / `accessResources` query parameters. Response:
 * `{ code: 0, data: { forbiddenTables, forbiddenColumns } }`. Anything else —
 * timeout, non-2xx, malformed body, `code !== 0` — is fail-closed.
 */
export class RemotePolicyClient {
  /**
   * @param config remote policy configuration.
   * @param options injectable clock and fetch for tests.
   */
  constructor(config, options = {}) {
    this.url = typeof config.policyApiUrl === 'string' ? config.policyApiUrl.trim() : ''
    this.token = typeof config.policyApiToken === 'string' ? config.policyApiToken : ''
    this.timeoutMs = Number.isFinite(config.apiTimeoutMs) && config.apiTimeoutMs > 0
      ? config.apiTimeoutMs
      : 3000
    this.cacheTtlMs = Number.isFinite(config.cacheTtlMs) && config.cacheTtlMs > 0
      ? config.cacheTtlMs
      : 30000
    this.tenantId = typeof config.tenantId === 'string' ? config.tenantId : ''
    this.userId = typeof config.userId === 'string' ? config.userId : ''
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch
    this.now = options.now ?? (() => Date.now())
    /** Latest successful snapshot, shared by every tenant/user in one process. */
    this.snapshot = undefined
    /** Failures are cached briefly so a dead endpoint cannot stall every call. */
    this.failureUntil = 0
    this.lastFailure = undefined
  }

  /** Whether a remote fetch is configured at all. */
  get configured() {
    return this.url !== ''
  }

  /**
   * Read the current policy, using the cache when it is fresh.
   * @returns the cached or newly fetched policy.
   * @throws when the endpoint is unreachable, slow, or answers with a refusal.
   */
  async read() {
    if (!this.configured) throw new Error('remote policy API is not configured')
    const now = this.now()
    if (this.snapshot !== undefined && this.snapshot.fresh(now, this.cacheTtlMs)) return this.snapshot.policy
    if (now < this.failureUntil) throw this.lastFailure ?? new Error('remote policy API recently failed')
    const policy = await this.fetchPolicy()
    this.snapshot = new RemoteSnapshot(policy, now)
    this.failureUntil = 0
    this.lastFailure = undefined
    return policy
  }

  /** Perform one GET and validate its envelope. */
  async fetchPolicy() {
    const url = new URL(this.url)
    if (this.tenantId !== '') url.searchParams.set('tenantId', this.tenantId)
    if (this.userId !== '') url.searchParams.set('userId', this.userId)
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), this.timeoutMs)
    try {
      const response = await this.fetchImpl(url, {
        method: 'GET',
        headers: {
          accept: 'application/json',
          ...this.token === '' ? {} : { authorization: `Bearer ${this.token}` },
        },
        signal: controller.signal,
      })
      if (response.status < 200 || response.status >= 300) {
        throw new Error(`remote policy API answered HTTP ${response.status}`)
      }
      const body = await response.json()
      return validatePolicyEnvelope(body)
    } catch (error) {
      this.lastFailure = error instanceof Error ? error : new Error(String(error))
      // A short negative cache keeps one dead endpoint from costing a timeout
      // on every single tool call; the next window retries.
      this.failureUntil = this.now() + Math.min(this.cacheTtlMs, 5000)
      throw this.lastFailure
    } finally {
      clearTimeout(timer)
    }
  }
}

/**
 * Accept only the documented response envelope.
 * @param body parsed JSON body.
 * @returns the normalised policy.
 * @throws on a malformed body, a non-zero `code`, or a wrong `data` shape.
 */
export function validatePolicyEnvelope(body) {
  if (body === null || typeof body !== 'object') throw new Error('remote policy body is not an object')
  const record = body
  if (record.code !== 0) throw new Error(`remote policy API refused with code ${String(record.code)}`)
  const data = record.data
  if (data === null || typeof data !== 'object') throw new Error('remote policy body carries no data object')
  const tables = Array.isArray(data.forbiddenTables) ? data.forbiddenTables : []
  const columns = Array.isArray(data.forbiddenColumns) ? data.forbiddenColumns : []
  const grantedTables = Array.isArray(data.grantedTables) ? data.grantedTables : []
  const grantedColumns = Array.isArray(data.grantedColumns) ? data.grantedColumns : []
  const strings = (list) => list.filter(item => typeof item === 'string' && item.trim() !== '')
  return {
    forbiddenTables: strings(tables),
    forbiddenColumns: strings(columns),
    grantedTables: strings(grantedTables),
    grantedColumns: strings(grantedColumns),
  }
}

/**
 * Merge the local static policy with the remote one.
 *
 * Grants come from two places so `whitelist_emulate` is usable without a policy
 * center: the locally configured list, and whatever the remote answered. Both
 * are additive — a deployment can start local-only and add the center later
 * without rewriting its rules.
 *
 * @param local local blacklist configuration, optionally carrying
 *   `grantedTables` / `grantedColumns` for the local whitelist.
 * @param remote fetched remote policy, or undefined when unfetched.
 * @returns the merged forbidden and granted sets plus the policy source label.
 */
export function mergePolicy(local, remote) {
  const forbiddenTables = [...(local.tables ?? [])]
  const forbiddenColumns = [...(local.columns ?? [])]
  const grantedTables = [...(local.grantedTables ?? [])]
  const grantedColumns = [...(local.grantedColumns ?? [])]
  if (remote !== undefined) {
    forbiddenTables.push(...(remote.forbiddenTables ?? []))
    forbiddenColumns.push(...(remote.forbiddenColumns ?? []))
    grantedTables.push(...(remote.grantedTables ?? []))
    grantedColumns.push(...(remote.grantedColumns ?? []))
  }
  const hasLocalGrants = grantedTables.length > 0 || grantedColumns.length > 0
  return {
    forbiddenTables,
    forbiddenColumns,
    grantedTables,
    grantedColumns,
    policySource: remote === undefined ? 'local' : 'local+remote',
    /** Whether any grant exists at all, so the UI can explain an all-deny state. */
    hasGrants: hasLocalGrants,
  }
}
