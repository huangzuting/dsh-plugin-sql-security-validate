/**
 * The database as the oracle.
 *
 * The question this harness answers is narrow and mechanical: *for this exact
 * statement, which tables did MySQL actually read?* Whatever the answer is, the
 * extractor must have named at least those tables. No one has to guess which
 * obfuscations exist — the server's own parser defines the truth for the
 * deployment, and it changes with the server rather than with our assumptions.
 *
 * Reading the tables is done with `performance_schema`: the counter for a table
 * is sampled before and after the statement, and the difference is what the
 * statement touched. That is far more reliable than matching strings in the SQL
 * — a `UNION SELECT … FROM other_table` hides the second table from any textual
 * heuristic but not from the storage engine.
 *
 * Safety: the account is SELECT-only on a throwaway schema, so a payload that
 * tries to write fails instead of damaging anything, and that failure is itself
 * a valid observation.
 */
import { spawnSync } from 'node:child_process'

/** Configuration, all overridable so the harness is not tied to one machine. */
export function configFromEnv() {
  return {
    container: process.env.SQLGUARD_MYSQL_CONTAINER ?? 'agentos-mysql',
    user: process.env.SQLGUARD_MYSQL_USER ?? 'sqlguard_oracle',
    password: process.env.SQLGUARD_MYSQL_PASSWORD ?? 'Oracle@12345',
    database: process.env.SQLGUARD_MYSQL_DB ?? 'sqlguard_probe',
    timeoutMs: Number(process.env.SQLGUARD_TIMEOUT_MS ?? 15000),
  }
}

/**
 * Run one batch of SQL through the `mysql` client inside a container.
 *
 * @param config oracle configuration
 * @param sql the script to run
 * @returns raw stdout, exit status, and stderr
 */
function runMysql(config, sql) {
  const result = spawnSync(
    'docker',
    [
      'exec', '-i', config.container,
      'mysql',
      `-u${config.user}`,
      `-p${config.password}`,
      '-N', '-B', '--force',
      `--default-character-set=utf8mb4`,
      `--connect-timeout=5`,
      config.database,
    ],
    { input: sql, encoding: 'utf8', timeout: config.timeoutMs },
  )
  return {
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    status: result.status,
    failedToSpawn: result.error !== undefined,
  }
}

/**
 * Sample the per-table read counters of the sandbox schema.
 *
 * @param config oracle configuration
 * @returns map of `schema.table` to read count
 */
export function readCounters(config) {
  const sql = `SELECT CONCAT(OBJECT_SCHEMA, '.', OBJECT_NAME), COUNT_READ
FROM performance_schema.table_io_waits_summary_by_table
WHERE OBJECT_SCHEMA = ${JSON.stringify(config.database)}
  AND COUNT_READ > 0;
`
  const { stdout } = runMysql(config, sql)
  const counters = new Map()
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim()
    if (trimmed === '') continue
    const [name, count] = trimmed.split('\t')
    if (name === undefined || count === undefined) continue
    counters.set(name, Number(count))
  }
  return counters
}

/**
 * Diff two counter samples into the tables read in between.
 *
 * @param before sample taken before the statement
 * @param after sample taken after it
 * @returns sorted table names that were read
 */
function diffCounters(before, after) {
  const touched = []
  for (const [name, count] of after) {
    const previous = before.get(name) ?? 0
    if (count > previous) touched.push(name)
  }
  return touched.sort()
}

/**
 * Execute one statement and report what the server did with it.
 *
 * @param config oracle configuration
 * @param statement the SQL to run
 * @param before counters sampled immediately before this call
 * @returns outcome, the tables actually read, and the counters to reuse next
 */
export function execute(config, statement, before) {
  const started = Date.now()
  const result = runMysql(config, `${statement}\n`)
  const elapsed = Date.now() - started
  const after = readCounters(config)

  const errorMatch = /ERROR (\d+)/.exec(result.stderr)
  return {
    ok: result.status === 0 && errorMatch === null,
    errorCode: errorMatch === null ? undefined : Number(errorMatch[1]),
    errorText: errorMatch === null
      ? undefined
      : result.stderr.split('\n').find(line => line.includes('ERROR'))?.trim(),
    tablesRead: diffCounters(before, after),
    rowOutput: result.stdout.trim(),
    elapsedMs: elapsed,
    // The next statement starts from this sample, halving the number of round trips.
    counters: after,
  }
}

/**
 * Check that the sandbox schema and the oracle account are usable.
 *
 * @param config oracle configuration
 * @returns a human-readable problem, or undefined when the oracle is ready
 */
export function checkOracle(config) {
  const probe = runMysql(config, 'SELECT 1;\n')
  if (probe.failedToSpawn) return 'docker is not available on PATH'
  if (probe.status !== 0) {
    const reason = probe.stderr.split('\n').find(line => line.includes('ERROR')) ?? probe.stderr.trim()
    return `cannot query the oracle (${reason || `exit ${probe.status}`})`
  }
  const tables = runMysql(config, 'SHOW TABLES;\n')
  if (!tables.stdout.includes('allowed_table') || !tables.stdout.includes('forbidden_table')) {
    return 'sandbox schema is missing; run tests/differential/setup.sql first'
  }
  return undefined
}
