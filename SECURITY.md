# Security Policy

This plugin's single responsibility is to stop SQL that exceeds an agent's
permissions. When someone finds a way around it, that must reach the maintainer
privately — a bypass disclosed in a public issue is a bypass in the wild.

## Supported versions

| Version | Status |
| --- | --- |
| 1.0.x | Supported |

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use either channel:

- GitHub private vulnerability reporting:
  `TODO: https://github.com/<your-account>/dsh-plugin-sql-security-validate/security/advisories/new`
- Email: <641694064@qq.com>

Please include:

- the affected version;
- the smallest SQL payload that reproduces it;
- the policy configuration in use (`securityMode`, and the contents of the
  blacklist or whitelist);
- what actually happened versus what should have happened.

A statement that was **allowed when it should have been refused** is the most
serious class of report for this project. A statement that was **refused when it
should have been allowed** matters too — over-blocking makes the agent unusable,
which is itself a failure of the plugin's purpose.

## Response targets

| Stage | Target |
| --- | --- |
| Acknowledgement | 3 business days |
| Initial assessment | 7 business days |
| Fix released | typically within 30 days, depending on severity |

## Known boundaries (not vulnerabilities)

The following are deliberate design decisions. They are listed here so that a
report about them can be answered quickly, and so that a real bypass is not
mistaken for one of them.

1. **Scope of enforcement.** Only SQL issued by an AI agent through a registered
   tool is checked. MCP service-layer auth, network/IP controls, and database
   account permissions are out of scope, as is any platform-level route that
   reaches the database without going through a registered tool.

2. **Schema discovery is on by default.** `allowSchemaDiscovery: true` permits
   `SHOW TABLES` / `SHOW DATABASES`, which reveals database and table names. An
   agent that cannot enumerate tables cannot write a valid query, so this is on
   by default. Turn it off where table names themselves are confidential.

   Note that `DESCRIBE` / `SHOW CREATE TABLE` are governed per table regardless
   of this setting: you can inspect the shape of a table you may read, and not
   one you may not.

3. **Unparseable statements are allowed by default.** With
   `failOnParseError: false`, a statement the parser cannot interpret passes
   through unjudged. MySQL has many legacy forms the vendored parser rejects, so
   refusing them all would break working queries. Enable it where the grammar in
   use is known to be covered.

4. **Audit SQL is stored in plaintext by default.** `audit.redactSql: false`
   keeps literal values in the audit log, because investigating an incident
   usually requires the actual statement. Set it to `true` to mask string
   literals.

5. **A bare table name in a whitelist spans databases.** A grant written as
   `user` matches `demo.user` *and* `mysql.user`, because an unqualified name
   carries no database to compare against. Configure `database.table`, or enable
   `strictDatabaseQualification` to restrict a bare grant to bare references.

## Third-party components

This plugin vendors `node-sql-parser` 5.4.0 (Apache-2.0) and `big-integer`
(MIT) under `vendor/`. The vendored copy is what runs.

**Upstream security fixes do not arrive automatically.** When `node-sql-parser`
publishes a fix, this plugin keeps using the vendored copy until someone
re-vendors it. Maintainers should watch the upstream security advisories and
re-vendor deliberately: install the new version in a scratch directory, copy the
same subset (see `vendor/node-sql-parser/README.md`), update the version noted
there, and run the full test suite.

The same applies to `big-integer`, which the parser depends on.

## What to do if you run this in production

- Write whitelist entries as `database.table`, not bare table names.
- Keep `auditEnable: true` and ship the JSONL log somewhere durable; the
  in-memory ring is bounded and is lost on restart.
- Review the effective policy from the settings panel before rollout — the panel
  shows the same decision path the interceptor uses.
