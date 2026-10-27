/**
 * The interception audit log.
 *
 * Every candidate SQL the plugin evaluates produces one record: the original
 * SQL, the outcome, the exact refused resources, the policy source, the
 * interception engine, and the session identity. Records live in a bounded
 * in-memory ring for live reads and, when a log file is configured, are also
 * appended to a JSONL file under the Harness home so a restart keeps history.
 *
 * The durable sink is deliberately optional and fail-soft: the audit file
 * failing costs history, never safety, so a write problem logs a warning and
 * never blocks a decision. The file is append-only — one JSON object per line —
 * so a truncated tail costs at most the last record.
 *
 * @module dsh-plugin-sql-security-validate/src/audit
 */

import { appendFile, mkdir, rm, stat } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { homedir } from 'node:os'

/** Directory under the Harness home that owns this plugin's durable files. */
const HOME_SEGMENTS = ['sql-security-validate']

/** Filename of the append-only audit log. */
const AUDIT_FILENAME = 'audit.jsonl'

/**
 * Resolve the Harness home the same way the launcher does: an explicit
 * `$DSH_HOME`, else `~/.dsh`. Read per call so a launch override applies.
 * @param env process environment.
 * @returns the absolute Harness home path.
 */
export function dshHome(env = process.env) {
  const configured = env.DSH_HOME
  const root = typeof configured === 'string' && configured.trim() !== ''
    ? configured
    : join(homedir(), '.dsh')
  return root
}

/**
 * Default audit file path for this Harness home.
 * @param env process environment.
 * @returns absolute JSONL path.
 */
export function defaultAuditPath(env = process.env) {
  return join(dshHome(env), ...HOME_SEGMENTS, AUDIT_FILENAME)
}

/**
 * Replace literal values so an audit trail never keeps a secret a query
 * happened to carry. Identifiers, keywords and structure survive.
 * @param sql original statement.
 * @returns the statement with string literals masked.
 */
export function redactSql(sql) {
  return String(sql).replace(/'([^']|'')*'/g, "'***'")
}

/** In-memory ring plus the optional append-only file sink. */
export class AuditLog {
  /**
   * @param options retained record count, SQL redaction, and the log file path.
   */
  constructor(options = {}) {
    this.maxRecords = Number.isFinite(options.maxRecords) && options.maxRecords > 0 ? options.maxRecords : 5000
    this.redactSql = options.redactSql === true
    this.path = typeof options.path === 'string' && options.path !== '' ? options.path : ''
    /** @type {Array<Record<string, any>>} oldest first. */
    this.records = []
    this.nextSeq = 1
    this.logger = console
    /** Serialises file writes so records land in order. */
    this.writes = Promise.resolve()
    this.fileAvailable = this.path !== ''
  }

  /**
   * Load the tail of an existing log so a restart shows history, not a gap.
   * A missing or unreadable file is not an error: the ring simply starts empty.
   * @returns resolution after the tail is loaded.
   */
  async hydrate() {
    if (this.path === '') return
    try {
      const info = await stat(this.path)
      // Read at most a bounded tail: the ring only keeps `maxRecords` anyway.
      const handle = await import('node:fs/promises')
      const text = await handle.readFile(this.path, 'utf8')
      void info
      const lines = text.split('\n')
      const parsed = []
      for (const line of lines) {
        if (line.trim() === '') continue
        try {
          const record = JSON.parse(line)
          if (this.accepts(record)) parsed.push(record)
        } catch {
          // A torn final line (process killed mid-write) is skipped, not fatal.
        }
      }
      this.records = parsed.slice(-this.maxRecords)
      for (const record of this.records) this.nextSeq = Math.max(this.nextSeq, record.seq + 1)
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        this.fileAvailable = false
        this.logger.warn('sql-security-validate: audit log could not be read; keeping the in-memory ring only: %s', String(error?.message ?? error))
      }
    }
  }

  /**
   * Structural check for one stored line.
   * @param record parsed JSON value.
   * @returns whether it is a record this version can read.
   */
  accepts(record) {
    return record !== null && typeof record === 'object'
      && Number.isInteger(record.seq) && Number.isInteger(record.time)
      && typeof record.toolName === 'string' && typeof record.sql === 'string'
  }

  /**
   * Append one record. Never throws: a failed file write logs and continues.
   * @param entry the record fields without `seq` and `time`.
   * @returns the stored record.
   */
  append(entry) {
    const record = {
      seq: this.nextSeq++,
      time: Date.now(),
      sessionId: String(entry.sessionId ?? ''),
      /** Session turn this call belonged to; -1 when the caller could not tell. */
      turn: Number.isInteger(entry.turn) ? entry.turn : -1,
      toolName: String(entry.toolName ?? ''),
      callId: String(entry.callId ?? ''),
      outcome: entry.outcome === 'deny' ? 'deny' : 'allow',
      securityMode: entry.securityMode === 'whitelist_emulate' ? 'whitelist_emulate' : 'blacklist',
      interceptMode: entry.interceptMode === 'guard' ? 'guard' : 'pre-execute',
      policySource: String(entry.policySource ?? 'local'),
      reason: String(entry.reason ?? ''),
      forbiddenTables: [...(entry.forbiddenTables ?? [])],
      forbiddenColumns: [...(entry.forbiddenColumns ?? [])],
      /**
       * The policy entries that actually matched, so the panel can answer
       * "命中了哪条策略" instead of only "哪张表被拒". A refused table and the
       * rule that refused it are different facts.
       */
      matchedRules: [...(entry.matchedRules ?? [])],
      /** Every table the statement touched, so an allow shows what was inspected. */
      inspectedTables: [...(entry.inspectedTables ?? [])],
      /** Statement kinds (`select`, `update`, …) for a quick read of intent. */
      statements: [...(entry.statements ?? [])],
      sql: this.redactSql ? redactSql(entry.sql) : String(entry.sql ?? ''),
    }
    this.records.push(record)
    if (this.records.length > this.maxRecords) {
      this.records.splice(0, this.records.length - this.maxRecords)
    }
    this.persist(record)
    return record
  }

  /**
   * Queue one line for the file sink. Failures disable the sink instead of
   * retrying on every call, so one bad path cannot slow the tool pipeline.
   * @param record stored record.
   */
  persist(record) {
    if (!this.fileAvailable || this.path === '') return
    const line = `${JSON.stringify(record)}\n`
    this.writes = this.writes.then(async () => {
      try {
        await mkdir(dirname(this.path), { recursive: true })
        await appendFile(this.path, line, 'utf8')
      } catch (error) {
        this.fileAvailable = false
        this.logger.warn('sql-security-validate: audit log write failed; continuing in memory only: %s', String(error?.message ?? error))
      }
    })
  }

  /** @returns a newest-first copy for a live read. */
  list() {
    return [...this.records].reverse()
  }

  /** Drop every record, in memory and on disk. */
  async clear() {
    this.records = []
    this.nextSeq = 1
    if (this.path === '') return
    await this.writes
    try {
      await rm(this.path, { force: true })
      this.fileAvailable = true
    } catch (error) {
      this.logger.warn('sql-security-validate: audit log could not be cleared: %s', String(error?.message ?? error))
    }
  }
}
