# 运维配置手册

面向企业部署：如何把本插件从「默认轻量」加固成「生产强安全」，以及每项开关的含义与风险。

## 1. 三档部署形态

| 形态 | 适用 | 关键配置 |
| --- | --- | --- |
| 轻量（默认） | 个人、测试、内网试用 | 全部默认值，只填本地黑名单 |
| 标准生产 | 企业 AI 问数 | `enableStrictGuardMode: true` + 远程策略 |
| 强隔离 | 政务、金融、央企、多租户 | 上述 + `securityMode: whitelist_emulate` |

## 2. 轻量形态

```yaml
- id: sql-security-validate
  name: dsh-plugin-sql-security-validate
  config:
    enable: true
    auditEnable: true
    securityMode: blacklist
    localBlacklist:
      tables:
        - db.admin
        - db.sensitive_log
      columns:
        - db.user.phone
        - db.user.idcard
        - db.user.bank_no
```

行为：策略未禁止即放行；命中即拒绝并返回结构化原因。

## 3. 标准生产形态

```yaml
- id: sql-security-validate
  name: dsh-plugin-sql-security-validate
  config:
    enable: true
    auditEnable: true
    securityMode: blacklist
    enableStrictGuardMode: true        # ← 打开单调守卫
    localBlacklist:
      tables: [db.admin, db.sensitive_log]
      columns: [db.user.phone, db.user.idcard, db.user.bank_no]
    remotePolicy:
      enabled: true
      policyApiUrl: https://policy.internal.example.com/api/v1/db-access
      policyApiToken: !!js process.env.DSH_SQL_POLICY_TOKEN
      apiTimeoutMs: 3000
      cacheTtlMs: 30000
      tenantId: !!js process.env.DSH_TENANT_ID ?? ''
      userId: ''
    audit:
      maxRecords: 20000
      redactSql: true
```

### 3.1 为什么打开 `enableStrictGuardMode`

普通 `tools/pre-execute` 是**可扩展瀑布**：另一个插件在后置位置返回 `allow`，理论上可以
覆盖本插件的拒绝。`ctx.tools.guard()` 是 DSH 的**单调守卫**——只有「拒绝」和
「不表态」两种结果，没有任何插件能把已拒绝的调用改回放行。

代价与约束：

- 守卫必须**同步**。远程策略只使用已缓存值；缓存尚未就绪时按 fail-closed 拒绝。
  因此 `cacheTtlMs` 不宜过大，且在策略中台不可用期间所有 SQL 调用都会被拒绝。
- 打开后策略中台成为硬依赖。若要保留「中台故障时降级为仅本地策略」，请保持
  `enableStrictGuardMode: false`（默认），此时中台故障仍按 fail-closed 拒绝，但拒绝
  发生在可扩展引擎中。

### 3.2 Token 不要写进 patch 文件

`policyApiToken` 的 schema 角色是 `secret`，设置页只显示「已设置/未设置」，不会回显。
但在 `cordis.patch.yml` 里直接写明文等于把密钥交给版本库——用 `!!js process.env.X`
从环境变量读取。

## 4. 强隔离形态（白名单模拟）

```yaml
- id: sql-security-validate
  name: dsh-plugin-sql-security-validate
  config:
    securityMode: whitelist_emulate
    enableStrictGuardMode: true
    remotePolicy:
      enabled: true
      policyApiUrl: https://policy.internal.example.com/api/v1/db-access
      policyApiToken: !!js process.env.DSH_SQL_POLICY_TOKEN
```

语义：**无许可即禁止**。远程返回的 `grantedTables` / `grantedColumns` 决定放行面：

- `grantedTables: ["db.user"]` → 该表及其全部字段可读
- `grantedColumns: ["db.user.phone"]` → 仅该字段（其余字段仍需表级授权）
- `grantedTables: ["db.*"]` → 该库全放行（谨慎使用）

注意：白名单模式下，若策略中台返回空数组且未配置任何 grant，**所有 SQL 都会被拒绝**。
上线前务必先用只读探针验证一遍授权响应。

## 5. 审计日志运维

默认落盘位置：`$DSH_HOME/sql-security-validate/audit.jsonl`（一行一条 JSON）。

- 只追加，轮转由外部工具负责（logrotate / journald / OSS 采集）。
- 内存环保留最新 `audit.maxRecords` 条，供设置页即时读取。
- 写入故障是 fail-soft：日志告警后转为仅内存，不影响工具调用。
- `audit.redactSql: true` 会把字符串字面量替换成 `'***'`，适合含 PII 的环境。

快速核查最近拒绝：

```bash
tail -n 200 ~/.dsh/sql-security-validate/audit.jsonl | grep '"outcome":"deny"'
```

## 6. 故障排查

| 现象 | 原因 | 处置 |
| --- | --- | --- |
| 所有 SQL 被拒绝，原因是「远程权限中台不可用」 | 中台超时/5xx/`code != 0`/结构非法 | 检查 `policyApiUrl` 与网络；必要时先关闭 `remotePolicy.enabled` 让插件退化为仅本地策略 |
| 明明有权限仍被拒绝（白名单模式） | 中台未返回对应 grant | 用审计日志里的 `forbiddenTables/Columns` 对照中台配置 |
| `planner` 之外的库表未被拦截 | 工具名不在 `targetToolPrefixes` | 补前缀，或打开 `includeNonMcpSqlTools` |
| SQL 未被识别 | 参数键不在 `sqlParamKeys` | 补键；值必须是真正的 SQL 文本 |
| 启用强依赖校验后插件起不来 | `requiredBundles` 里某 bundle 未选中 | 补选 bundle，或关闭 `enableBundleRequireLock` |

## 7. 卸载

1. 若开启过 `enableAntiUnmount`，先把它设为 `false`。
2. 在 **设置 → 插件** 停用，或调用 `plugin_manager action=remove_bundle`。
3. 需要的话删除 `$DSH_HOME/sql-security-validate/` 审计目录。
