/**
 * SQL resource extraction, backed by a real AST parser.
 *
 * ## Why an AST and not a tokenizer
 *
 * The previous hand-written tokenizer only recognised a table reference after
 * `FROM` / `JOIN` / `INTO` / `UPDATE`. Metadata statements put the table
 * somewhere else entirely — `DESCRIBE admin`, `SHOW CREATE TABLE admin`,
 * `SHOW TABLE STATUS LIKE 'sensitive_log'` — so they yielded an empty table set
 * and sailed past every policy. `SHOW COLUMNS FROM x` only appeared to work
 * because `COLUMNS` was mistaken for a column name and happened to be
 * unauthorised; that is coincidence, not coverage.
 *
 * A real AST reports the target of every statement kind, so schema-discovery
 * statements can be governed by the *same table policy* as `SELECT` — the AI
 * can still inspect a table's shape when it may read that table, and still
 * cannot inspect one it may not.
 *
 * ## What this module guarantees
 *
 * - `tables` / `columns` are lowercased, schema-qualified where the statement
 *   qualified them, and alias-free (`FROM user u` yields `user`, not `u`).
 * - `kind` names the statement type (`select`, `desc`, `show`, `insert`, …).
 * - `metadata` marks statements that describe schema rather than read rows.
 * - Text the parser rejects yields `isSql: false` plus `parseError`; the caller
 *   decides what to do. This module never guesses.
 *
 * The parser is vendored under `vendor/node-sql-parser` (see its README) so the
 * plugin neither downloads 88 MB at install time nor floats on a version range.
 *
 * @module dsh-plugin-sql-security-validate/src/sql-parse
 */

import { createRequire } from 'node:module'

/** Load the vendored CommonJS parser from the plugin's own directory. */
const require = createRequire(import.meta.url)
const { Parser } = require('../vendor/node-sql-parser/index.cjs')
const parser = new Parser()

/** Statements that describe schema instead of reading rows. */
const METADATA_KINDS = new Set(['desc', 'show', 'explain'])

/** Statements that change data or structure. */
const MUTATING_KINDS = new Set([
  'insert', 'update', 'delete', 'replace', 'create', 'drop', 'alter',
  'truncate', 'rename', 'grant', 'revoke', 'load_data',
])

/** Leading keywords that mark a string as SQL worth parsing at all. */
const SQL_START = /^\s*(?:select|with|insert|update|delete|replace|merge|create|drop|alter|truncate|rename|grant|revoke|explain|describe|desc|show|call|set|use|analyze|optimize|repair|check|prepare|execute|deallocate|lock|unlock|load|copy|begin|start|commit|rollback|savepoint)\b/i

/**
 * Words that may FOLLOW a leading keyword and still describe a SQL statement.
 *
 * `explain the numbers` starts like SQL but is prose. Real statements put a
 * clause keyword, an identifier, or punctuation next — never a bare English
 * article. Requiring this keeps prose out of the policy pipeline, where it would
 * otherwise be judged (and possibly refused) as a query.
 */
const SQL_BODY = /^\s*(?:select|with|insert|update|delete|replace|merge|create|drop|alter|truncate|rename|grant|revoke|analyze|optimize|repair|check|load|copy|begin|start|commit|rollback|savepoint|call|set|use|prepare|execute|deallocate|lock|unlock)\b/i

/**
 * Rewrite MySQL executable comments into the code they run.
 *
 * MySQL runs the body of `/*! … *\/` (optionally version-gated, as in
 * `/*!50000 … *\/`). Treating it as an ordinary comment is a bypass: the
 * statement disappears from the extractor's view while the server executes it.
 * Several obfuscations are built on exactly this, including
 * `/*!50000SELECT*\/ …` where the comment supplies the keyword itself.
 *
 * The scan is quote-aware so a `/*!` inside a string literal is left alone.
 * Ordinary comments and optimizer hints (`/*+ … *\/`) are preserved verbatim.
 *
 * @param text candidate text
 * @returns the text with executable comments replaced by their bodies
 */
function expandExecutableComments(text) {
  let out = ''
  let index = 0
  let quote = ''
  while (index < text.length) {
    const char = text[index]
    if (quote !== '') {
      out += char
      // Backslash escapes apply inside '…' and "…" but not inside `…`.
      if (char === '\\' && quote !== '`') {
        out += text[index + 1] ?? ''
        index += 2
        continue
      }
      if (char === quote) quote = ''
      index += 1
      continue
    }
    if (char === "'" || char === '"' || char === '`') {
      quote = char
      out += char
      index += 1
      continue
    }
    if (char === '/' && text[index + 1] === '*') {
      const end = text.indexOf('*/', index + 2)
      // Unterminated: the rest is still inside the comment.
      if (end === -1) return out
      if (text[index + 2] === '!') {
        // Drop the optional version gate; what follows it is the SQL body.
        out += ` ${text.slice(index + 3, end).replace(/^\d+/, '')} `
      } else {
        out += text.slice(index, end + 2)
      }
      index = end + 2
      continue
    }
    out += char
    index += 1
  }
  return out
}

/**
 * Strip leading whitespace, comments and empty statements.
 *
 * A statement may open with `-- …`, `# …`, `/* … *\/` or a stray `;`. The SQL
 * keyword test anchors on the first word, so without this the statement was
 * unrecognisable — and an unrecognised statement is not judged at all, which
 * turned a comment into a way past every policy.
 *
 * Only LEADING noise is removed. Comments inside the statement are left for the
 * parser, which handles them.
 *
 * @param text candidate text
 * @returns the text with leading whitespace, comments and `;` removed
 */
function stripLeadingNoise(text) {
  let rest = text.trimStart()
  for (;;) {
    if (rest.startsWith(';')) {
      rest = rest.slice(1).trimStart()
      continue
    }
    if (rest.startsWith('--') || rest.startsWith('#')) {
      const newline = rest.indexOf('\n')
      // A line comment with no newline after it leaves no statement to inspect.
      if (newline === -1) return ''
      rest = rest.slice(newline + 1).trimStart()
      continue
    }
    if (rest.startsWith('/*')) {
      const end = rest.indexOf('*/', 2)
      // An unterminated block comment: everything after it is still commented.
      if (end === -1) return ''
      rest = rest.slice(end + 2).trimStart()
      continue
    }
    return rest
  }
}

/**
 * The view used only to decide whether text is SQL at all.
 *
 * Distinct from {@link stripLeadingNoise} because a leading `(` is meaningful to
 * the parser — `(SELECT …)` is valid MySQL — so it is dropped here for the
 * keyword test only, never from what gets parsed.
 *
 * @param text candidate text
 * @returns text beginning with the statement keyword, or empty
 */
function keywordView(text) {
  let rest = expandExecutableComments(text)
  for (;;) {
    rest = rest.trimStart()
    if (rest.startsWith(';') || rest.startsWith('(')) {
      rest = rest.slice(1)
      continue
    }
    const stripped = stripLeadingNoise(rest)
    if (stripped === rest) return rest
    rest = stripped
    if (rest === '') return ''
  }
}

/**
 * Decide whether a string is plausibly a SQL statement rather than prose that
 * happens to open with the same word.
 * @param text candidate text
 * @returns whether to hand it to the parser
 */
function looksLikeSql(text) {
  const trimmed = keywordView(text)
  // A statement keyword followed by anything other than an article reads as SQL.
  if (SQL_BODY.test(trimmed)) return true
  // `describe`, `desc`, `show`, `explain`: require a real target after the
  // keyword, so `explain the numbers` and `show me the data` stay prose.
  const meta = /^\s*(?:describe|desc|show|explain)\b\s*(.*)$/i.exec(trimmed)
  if (meta === null) return false
  const rest = meta[1].trim()
  if (rest === '') return false
  const first = rest.split(/\s+/)[0]
  // A bare English article/pronoun cannot begin a SQL target.
  if (/^(?:the|a|an|this|that|these|those|it|how|why|what|which|who)$/i.test(first)) return false
  // `SHOW` takes a fixed vocabulary; a sentence-like second word is prose.
  if (/^\s*show\b/i.test(trimmed)) {
    return /^(?:create|columns|index|indexes|keys|table|tables|databases|schemas|status|grants|variables|processlist|engines|triggers|procedure|function|events|plugins|collation|character|warnings|errors|open|profile|slave|master|replica|binary|binlog)$/i.test(first)
  }
  return true
}

/** Dialect the policy engine assumes. MySQL matches the MCP servers in use. */
const DIALECT = 'mysql'

/**
 * Lowercase one identifier, stripping the quote style its dialect uses.
 * @param value identifier text
 * @returns the bare lowercase name
 */
function bare(value) {
  if (typeof value !== 'string') return ''
  return value.replace(/^[`"[]/g, '').replace(/[`"\]]$/g, '').toLowerCase()
}

/**
 * Qualify a table reference the way the statement wrote it.
 * @param db database qualifier, if any
 * @param table table name
 * @returns `db.table` or `table`
 */
function qualify(db, table) {
  const name = bare(table)
  if (name === '') return ''
  const schema = typeof db === 'string' && db !== '' ? bare(db) : ''
  return schema === '' ? name : `${schema}.${name}`
}

function literalTarget(sql) {
  const like = /\blike\s+['"]([^'"]+)['"]/i.exec(sql)
  if (like !== null) return like[1]
  const where = /\bwhere\s+[\w.]*table[\w.]*\s*=\s*['"]([^'"]+)['"]/i.exec(sql)
  if (where !== null) return where[1]
  return undefined
}

/**
 * Recover the target of `DESCRIBE` / `DESC` when the parser rejects the form.
 *
 * The vendored parser accepts `DESCRIBE admin` but throws on the qualified
 * `DESCRIBE db.admin` (and its backticked spelling), which is valid MySQL. Only
 * the identifier after the keyword matters, so read it directly.
 *
 * @param sql the original statement text
 * @returns the qualified table name, or undefined
 */
function describeTarget(sql) {
  const match = /^\s*(?:describe|desc)\s+([`"[]?[\w$]+[`"\]]?(?:\s*\.\s*[`"[]?[\w$]+[`"\]]?)?)/i.exec(sql)
  if (match === null) return undefined
  const parts = match[1].split('.').map(part => bare(part.trim()))
  return parts.filter(part => part !== '')
}

function collectNode(node, out, bound = new Set()) {
  if (node === null || typeof node !== 'object') return
  if (Array.isArray(node)) {
    for (const item of node) collectNode(item, out, bound)
    return
  }

  const kind = typeof node.type === 'string' ? node.type : ''

  // A `WITH` clause binds names for THIS statement only. Copy the inherited
  // scope so a sibling statement never inherits another's CTE names.
  let scope = bound
  if (Array.isArray(node.with)) {
    scope = new Set(bound)
    for (const entry of node.with) {
      const rawName = entry?.name?.value ?? entry?.name
      if (typeof rawName === 'string' && rawName !== '') scope.add(bare(rawName))
    }
    for (const entry of node.with) {
      // The CTE body is a real query: its tables count.
      collectNode(entry?.stmt ?? null, out, scope)
    }
  }

  // `from` entries: `{ db, table, as }`, or `{ expr }` for a derived table.
  // Entries are remembered so the generic `table` handling below skips them: a
  // `from` entry owns a `table` slot too, and reading it twice would also add a
  // spurious unqualified name (`demo.user` yielding both `demo.user` and `user`).
  const fromEntries = new Set()
  if (Array.isArray(node.from)) {
    for (const entry of node.from) {
      if (entry === null || typeof entry !== 'object') continue
      fromEntries.add(entry)
      if (typeof entry.table === 'string') {
        // A bare name matching a bound CTE is that CTE, not a table.
        const isCte = entry.db == null && scope.has(bare(entry.table))
        if (!isCte) {
          const name = qualify(entry.db, entry.table)
          if (name !== '') out.tables.add(name)
        }
        // Remember the alias so `u.*` can be traced back to the table it covers.
        if (typeof entry.as === 'string' && entry.as !== '') {
          out.aliasToTable.set(bare(entry.as), qualify(entry.db, entry.table))
        }
      }
    }
  }

  // A projection of `*` exposes every column of the tables it covers, so a
  // column-level rule cannot be shown to hold. `COUNT(*)` is NOT this: it is an
  // `aggr_func` whose argument is a `star` node, and it reveals no column value,
  // so only a `column_ref` named `*` in the projection list counts.
  if (Array.isArray(node.columns)) {
    for (const item of node.columns) {
      const expr = item === null || typeof item !== 'object' ? undefined : item.expr
      if (expr === null || typeof expr !== 'object') continue
      if (expr.type !== 'column_ref' || expr.column !== '*') continue
      const alias = typeof expr.table === 'string' ? bare(expr.table) : ''
      if (alias === '') out.starAll = true
      else out.starAliases.add(alias)
    }
  }

  // A column reference is NOT a table: its `table` slot holds an alias
  // (`FROM user u` → `u.id`). Handled first so the table-slot branches below
  // never read it, and returned so its children are not walked as statements.
  if (node.type === 'column_ref') {
    if (typeof node.column === 'string') {
      const column = bare(node.column)
      if (column !== '' && column !== '*') {
        const alias = typeof node.table === 'string' ? bare(node.table) : ''
        out.columns.add(alias === '' ? column : `${alias}.${column}`)
      }
    }
    return
  }

  // A `table` slot: DESCRIBE (string), SHOW (`{db, table}`), DDL (array).
  if (typeof node.table === 'string' && !fromEntries.has(node)) {
    const name = qualify(null, node.table)
    if (name !== '') out.tables.add(name)
  } else if (node.table !== null && typeof node.table === 'object' && !Array.isArray(node.table)) {
    if (!fromEntries.has(node) && typeof node.table.table === 'string') {
      const name = qualify(node.table.db, node.table.table)
      if (name !== '') out.tables.add(name)
    }
  } else if (Array.isArray(node.table)) {
    for (const entry of node.table) {
      if (typeof entry === 'string') {
        const name = qualify(null, entry)
        if (name !== '') out.tables.add(name)
      } else if (entry !== null && typeof entry === 'object' && typeof entry.table === 'string') {
        const name = qualify(entry.db, entry.table)
        if (name !== '') out.tables.add(name)
      }
    }
  }

  // INSERT … : the target sits in `into`.
  if (node.into !== null && typeof node.into === 'object' && typeof node.into.table === 'string') {
    const name = qualify(node.into.db, node.into.table)
    if (name !== '') out.tables.add(name)
  }

  if (kind !== '') {
    if (out.kind === '') out.kind = kind
    out.statements.add(kind)
  }

  // Descend into every remaining child. `as` is an alias, never a resource.
  // A `from` entry is already handled above, so its own `table` slot must not be
  // read again — but anything it CONTAINS (a derived table's inner statement)
  // still must be. Descend with the entry marked as consumed.
  for (const [key, value] of Object.entries(node)) {
    if (key === 'as' || key === 'type') continue
    if (value === null || typeof value !== 'object') continue
    if (key === 'from' && Array.isArray(value)) {
      for (const entry of value) {
        if (entry !== null && typeof entry === 'object') collectChildren(entry, out, scope)
      }
      continue
    }
    collectNode(value, out, scope)
  }
}

/**
 * Walk only the children of a node, not the node's own slots.
 *
 * Used for `from` entries, whose `table`/`db` slots are read by the caller: a
 * derived table still needs its inner statement visited, but the entry's own
 * table name must not be collected twice.
 *
 * @param node a `from` entry
 * @param out accumulator
 * @param bound CTE names in scope
 */
function collectChildren(node, out, bound) {
  for (const [key, value] of Object.entries(node)) {
    if (key === 'as' || key === 'type' || key === 'table' || key === 'db') continue
    if (value !== null && typeof value === 'object') collectNode(value, out, bound)
  }
}

/**
 * Parse one statement and report every resource it touches.
 *
 * @param sql the statement text
 * @returns resources, statement kind, and whether the text parsed as SQL
 */
export function parseSql(sql) {
  const text = typeof sql === 'string' ? sql : ''
  // Executable comments are expanded first: MySQL runs their body, so what is
  // judged must be what runs. Leading comments are then dropped because they
  // carry no semantics and break keyword anchoring. The original text is what
  // callers log; only the shape is judged from the normalised form.
  const normalized = expandExecutableComments(text)
  const trimmed = stripLeadingNoise(normalized)
  if (trimmed === '') {
    return { isSql: false, kind: '', statementKinds: [], mutating: false, metadata: false, tables: [], columns: [], star: false, starTables: [] }
  }

  let ast
  try {
    ast = parser.astify(trimmed, { database: DIALECT })
  } catch (mysqlError) {
    // Bracket-quoted identifiers (`[admin]`) are T-SQL, not MySQL. A statement
    // that failed only because of its quote style still names a real table, so
    // retry once under that dialect before treating it as unparseable.
    let recovered
    if (trimmed.includes('[')) {
      try {
        recovered = parser.astify(trimmed, { database: 'transactsql' })
      } catch {
        recovered = undefined
      }
    }
    if (recovered === undefined) {
      // `DESCRIBE db.table` is valid MySQL the parser rejects; the target is a
      // plain identifier pair, so read it directly. Recovering it keeps schema
      // discovery governed by the same table policy as everything else.
      const described = /^\s*(?:describe|desc)\b/i.test(trimmed) ? describeTarget(trimmed) : undefined
      if (described !== undefined && described.length > 0) {
        return {
          isSql: true,
          kind: 'desc',
          statementKinds: ['desc'],
          mutating: false,
          metadata: true,
          tables: [described.join('.')],
          columns: [],
        }
      }
      // The parser rejects some legitimate MySQL forms outright, notably
      // `SHOW TABLE STATUS LIKE '<name>'`. Those still name their target, as a
      // predicate literal, so recover it before giving up: the statement is a
      // real schema-discovery request and must be governed, not silently allowed.
      const literal = literalTarget(trimmed)
      if (literal !== undefined) {
        return {
          isSql: true,
          kind: 'show',
          statementKinds: ['show'],
          mutating: false,
          metadata: true,
          tables: [bare(literal)],
          columns: [],
        }
      }
      // Unparseable text is reported, not guessed at. Whether that is fatal is
      // the caller's policy decision.
      return {
        isSql: looksLikeSql(trimmed),
        kind: '',
        statementKinds: [],
        mutating: false,
        metadata: false,
        tables: [],
        columns: [],
        parseError: true,
        cause: String(mysqlError?.message ?? mysqlError),
      }
    }
    ast = recovered
  }

  const statements = Array.isArray(ast) ? ast : [ast]
  const out = {
    tables: new Set(),
    columns: new Set(),
    kind: '',
    statements: new Set(),
    /** Set when a projection is a bare `*`, which expands to every column. */
    starAll: false,
    /** Aliases a `t.*` projection names, resolved against `aliasToTable`. */
    starAliases: new Set(),
    /** `FROM user u` → { u: 'user' }, so `u.*` can be traced to its table. */
    aliasToTable: new Map(),
  }
  for (const statement of statements) collectNode(statement, out)

  // A metadata statement may name its target only inside a predicate literal.
  if (out.tables.size === 0) {
    const literal = literalTarget(trimmed)
    if (literal !== undefined) out.tables.add(bare(literal))
  }

  // Which tables a `*` projection actually covers. An unqualified `*` covers
  // every table the statement reads; `u.*` covers the one `u` names.
  const starTables = new Set()
  if (out.starAll) for (const table of out.tables) starTables.add(table)
  for (const alias of out.starAliases) {
    const resolved = out.aliasToTable.get(alias)
    starTables.add(resolved === undefined || resolved === '' ? alias : resolved)
  }

  const kinds = [...out.statements].filter(entry => entry !== '')
  return {
    isSql: true,
    kind: out.kind,
    statementKinds: kinds,
    mutating: kinds.some(entry => MUTATING_KINDS.has(entry)),
    metadata: kinds.some(entry => METADATA_KINDS.has(entry)),
    tables: [...out.tables].sort(),
    columns: [...out.columns].sort(),
    star: starTables.size > 0,
    starTables: [...starTables].sort(),
  }
}

/**
 * Collect SQL candidates from one tool call's arguments.
 *
 * A tool may carry its statement under any configured key, so those keys are
 * scanned first and — when allowed — every string value. Each candidate is
 * parsed independently.
 *
 * A string counts as a candidate when it starts with a SQL keyword. It is kept
 * even when the parser finds no table: metadata discovery (`SHOW TABLES`) is a
 * legitimate, policy-governed operation, and dropping table-less statements here
 * is what previously left them both unpoliced and unaudited.
 *
 * @param args parsed tool arguments
 * @param options key list plus whether to scan outside the configured keys
 * @returns candidates in argument order
 */
export function collectSqlCandidates(args, options = {}) {
  const keys = Array.isArray(options.keys) && options.keys.length > 0
    ? options.keys
    : ['sql', 'query', 'statement', 'text', 'command']
  const includeOthers = options.includeOthers === true
  const candidates = []

  /**
   * @param value candidate string
   * @param origin argument key it came from
   */
  const push = (value, origin) => {
    if (typeof value !== 'string') return
    const trimmed = value.trim()
    if (trimmed.length < 6) return
    if (!looksLikeSql(trimmed)) return
    candidates.push({ sql: trimmed, origin, parsed: parseSql(trimmed) })
  }

  const visit = (value, origin) => {
    if (typeof value === 'string') { push(value, origin); return }
    if (Array.isArray(value)) { for (const item of value) visit(item, origin); return }
    if (value !== null && typeof value === 'object') {
      for (const [key, item] of Object.entries(value)) visit(item, key)
    }
  }

  if (args !== null && typeof args === 'object' && !Array.isArray(args)) {
    for (const key of keys) {
      if (Object.hasOwn(args, key)) visit(args[key], key)
    }
    if (includeOthers) {
      for (const [key, item] of Object.entries(args)) {
        if (!keys.includes(key)) visit(item, key)
      }
    }
  } else if (includeOthers) {
    visit(args, 'arguments')
  }
  return candidates
}
