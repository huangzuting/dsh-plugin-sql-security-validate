# dsh-plugin-sql-security-validate

[English](README.md) | [简体中文](README.zh.md)

**AI SQL 权限校验拦截插件** — DeepSeek Harness 通用 AI 数据库权限管控插件。

拦截智能体（Agent）生成的越权 SQL：**不静默改写、直接拒绝执行**，并把结构化权限
原因返回给模型，让模型自主剔除越权字段、更换统计口径，或用自然语言向用户解释权限不足。

- 插件 ID：`dsh-plugin-sql-security-validate`
- 适用框架：DeepSeek Harness（Cordis）
- 适配版本：DSH >= 0.1.x（本仓库验证于 0.2.0-rc.1）
- 开源协议：MIT

---

## 1. 它解决什么问题

| 问题 | 本插件的做法 |
| --- | --- |
| AI 自主生成越权 SQL，查询敏感表 / 敏感字段 | AST 解析全部资源，命中策略即拒绝执行 |
| 给 AI 的报错含糊，问答链路断裂 | 拒绝原因里带 `SQL_PERMISSION_DENIED` 与越权资源明细 |
| 静默改写导致 AI「以为数据完整」产生幻觉 | **永不改写 SQL**，拒绝是显式的 |
| 个人轻量使用 vs 企业强安全，两套形态 | 全部加固项默认关闭，生产按需开启 |
| 多插件环境下拒绝决策被后置插件覆盖 | 可选单调守卫 `ctx.tools.guard()`，拒绝不可推翻 |

## 2. 边界（对外免责，清晰闭环）

1. 本插件**仅防护 AI 智能体生成的越权 SQL**。
2. 不存在「AI 底层绕过 MCP」的风险：Agent 没有网络与协议权限，无法直连 MCP 服务，
   所有 MCP 请求必须经过 DSH Runtime 调度流水线
   （`Agent 输出工具调用 → 插件拦截层 → MCP 真实执行`）。
3. 插件层**唯一**的覆盖风险来自多插件事件顺序，已由可选 Guard 严格模式彻底封堵。
4. 不防护「平台多工具名绕过」——需要平台侧收敛 MCP 工具入口。
5. 不做 MCP 服务层、IP 层、账号层鉴权——那属于服务安全范畴。

## 3. 安装

在 DSH Web GUI 的 **插件市场** 或 **设置 → 插件** 中安装本 bundle，或在会话里让
Agent 调用：

```
plugin_manager action=install_bundle target=<本目录绝对路径>
```

安装后 bundle 会在 profile 中插入一行 `sql-security-validate`，默认即启用。

## 4. 配置

配置项分两组呈现：

- **设置 → 插件 → AI SQL 权限校验拦截插件**：可视化表单（由 Config schema 自动生成）。
- `cordis.patch.yml`：直接写 YAML，适合批量/版本化管理。

### 4.1 基础通用配置

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `enable` | boolean | `true` | 插件总开关 |
| `auditEnable` | boolean | `true` | 是否记录审计日志 |
| `securityMode` | enum | `blacklist` | `blacklist` / `whitelist_emulate` |

### 4.2 高级安全加固（默认全部关闭）

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `enableStrictGuardMode` | boolean | `false` | 单调守卫严格拦截（防插件覆盖） |
| `enableAntiUnmount` | boolean | `false` | 防卸载保护（生产加固） |
| `enableBundleRequireLock` | boolean | `false` | 强依赖校验 |
| `requiredBundles` | string[] | `[]` | 强依赖校验生效时必需的 bundle 包名 |

> 默认状态下：插件可随时卸载、无任何强制锁定、无启动强制依赖。

### 4.3 本地静态黑名单

| 配置项 | 默认值 |
| --- | --- |
| `localBlacklist.tables`（`db.table`） | `['db.admin', 'db.sensitive_log']` |
| `localBlacklist.columns`（`db.table.column`） | `['db.user.phone', 'db.user.idcard', 'db.user.bank_no']` |

### 4.3b 本地白名单（白名单模式无需中台）

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `localWhitelist.tables` | `[]` | 允许访问的表；允许整表时只写表名 |
| `localWhitelist.columns` | `[]` | 允许访问的字段，用于按字段授权 |

白名单模式下，本地白名单与远程中台返回的授权**取并集**。

### 4.4 远程动态权限 OpenAPI

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `remotePolicy.enabled` | `false` | 是否从权限中台拉取 |
| `remotePolicy.policyApiUrl` | `''` | 权限中台接口地址 |
| `remotePolicy.policyApiToken` | `''` | 接口鉴权 Token（`role('secret')`，不会被回显） |
| `remotePolicy.apiTimeoutMs` | `3000` | 超时时间（毫秒） |
| `remotePolicy.cacheTtlMs` | `30000` | 策略缓存时长（毫秒） |
| `remotePolicy.tenantId` | `''` | `tenantId` 查询参数 |
| `remotePolicy.userId` | `''` | `userId` 查询参数 |

### 4.5 拦截范围与审计（接线项）

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `targetToolPrefixes` | `['mcp__']` | 只拦截这些前缀开头的工具；MCP 工具名恒为 `mcp__<server>__<tool>` |
| `includeNonMcpSqlTools` | `false` | 是否同时检查前缀之外的工具 |
| `sqlParamKeys` | `['sql','query','statement','text','command']` | 参数中哪些键按 SQL 解析 |
| `allowSchemaDiscovery` | `true` | 是否允许不带表名的结构发现语句（`SHOW TABLES` / `SHOW DATABASES`）。关掉则连表名都不给 |
| `failOnParseError` | `false` | 是否拒绝解析器无法识别的语句。打开更安全但会误伤 MySQL 历史语法 |
| `strictDatabaseQualification` | `false` | 白名单里的裸表名是否可匹配带库名的资源。默认宽容（`user` 也放行 `mysql.user`）；打开后裸表名仅匹配裸名 |
| `audit.maxRecords` | `5000` | 内存环形缓冲保留条数 |
| `audit.redactSql` | `false` | 是否把字符串字面量替换为 `'***'` |
| `audit.logPath` | `''` | 追加写 JSONL 的路径；空表示 `$DSH_HOME/sql-security-validate/audit.jsonl` |

### 4.6 结构发现语句怎么判定

`DESCRIBE` / `SHOW` 这类描述表结构的语句，**与查询走同一套表级策略**：

| 语句 | 已授权表 | 未授权表 | 不指名表 |
| --- | --- | --- | --- |
| `DESCRIBE t` / `SHOW CREATE TABLE t` | 放行 | 拒绝 | — |
| `SELECT … FROM t` | 放行 | 拒绝 | — |
| `SHOW TABLES` / `SHOW DATABASES` | — | — | 由 `allowSchemaDiscovery` 决定 |

这样 AI 依然能发现有哪些表、查看授权表的结构，据此写出合规查询；但碰不到未授权表的结构。若把结构发现也一律拒绝，AI 将无从了解库内有什么，问数能力随之失效。

## 5. 权限模式

**黑名单模式（默认）** — 无策略即放行；命中本地或远程黑名单即拒绝。适合绝大多数企业 AI 问数场景。

**白名单模拟模式** — 无许可即禁止；仅放行「放行名单」里列出的资源。
放行名单有**两个来源，可叠加**：

1. **本地配置**（`localWhitelist`，面板「放行名单」文本域）——无需任何外部服务；
2. **远程权限中台**（`remotePolicy.grantedTables` / `grantedColumns`）——可选。

因此通用部署可以纯本地跑白名单，不依赖中台；需要集中管控时再接中台，
两边条目取并集。适合政务、金融、央企、多租户强隔离场景。

## 6. 双拦截引擎

| 引擎 | 触发条件 | 特点 |
| --- | --- | --- |
| `pre-execute`（默认） | 始终挂载 | 兼容性最强，可 `await` 远程策略 |
| `guard`（企业） | `enableStrictGuardMode: true` | 单调守卫，拒绝后任何后置插件都无法改回放行；同步判定，只用已缓存的远程策略 |

守卫是同步的，因此远程策略尚未取到时按 **fail-closed** 拒绝（宁可误拦，不可放过）。

## 7. 远程 OpenAPI 规范

请求：

```http
GET {policyApiUrl}?tenantId=xxx&userId=xxx
Authorization: Bearer {policyApiToken}
Accept: application/json
```

标准返回体：

```json
{
  "code": 0,
  "data": {
    "forbiddenTables": [],
    "forbiddenColumns": [],
    "grantedTables": [],
    "grantedColumns": []
  }
}
```

`grantedTables` / `grantedColumns` 供白名单模拟模式使用。

**降级策略**：接口超时 / 非 2xx / `code !== 0` / 结构非法 → **直接拒绝 SQL 执行（安全优先）**。
空数组 → 仅使用本地策略。

## 8. 越权拒绝返回结构

插件不修改 SQL、不静默放行、不隐性删减字段。校验失败时模型看到：

```json
{
  "success": false,
  "code": "SQL_PERMISSION_DENIED",
  "message": "当前SQL包含无权限访问的资源，已禁止执行",
  "detail": {
    "forbiddenTables": ["db.admin"],
    "forbiddenColumns": ["db.user.phone"],
    "securityMode": "blacklist",
    "interceptMode": "pre-execute",
    "policySource": "local+remote"
  }
}
```

模型收到后可自主执行：

1. 自动剔除越权字段重写 SQL；
2. 更换查询维度、更换统计方式；
3. 向用户用自然语言解释权限不足原因。

## 9. 执行链路

1. AI 生成 SQL 工具调用
2. 本插件 AST 解析所有表、字段资源（含 JOIN / 子查询 / CTE / 函数）
3. 合并【本地静态策略 + 远程中台策略】
4. 按拦截模式判断：`pre-execute` 拦截，或 `guard` 单调守卫拦截
5. 越权则拒绝执行、返回明细
6. 审计日志落库
7. AI 根据拒绝原因自主修正回答

## 10. 审计日志

每条记录包含：原始 SQL、校验结果（放行/拒绝）、越权资源明细、权限来源、拦截模式、
租户/用户信息、会话 ID、时间戳、工具名与 callId。

**两种读取方式：**

- **设置页面板**：设置 →「SQL 权限校验」。可直接操作，见下节。
- **JSONL 文件**：`$DSH_HOME/sql-security-validate/audit.jsonl`，一行一条 JSON，
  可直接 `tail` / `grep` / 交给日志采集。

### 设置页可以做什么

| 操作 | 说明 |
| --- | --- |
| 总开关 | 一键启用/停用拦截（停用后所有 SQL 直接放行） |
| 黑白名单切换 | `blacklist` ⇄ `whitelist_emulate` |
| 严格守卫开关 | 开/关 `enableStrictGuardMode` |
| 编辑黑名单 | 禁区表、禁区字段两个文本域 |
| 编辑白名单 | 放行表、放行字段两个文本域（**不需要权限中台**） |
| 审计明细 | 点任意一行展开：原始 SQL、**命中的具体策略条目**、检查到的表、权限来源、引擎、会话 |
| 清空审计 | 同时清空内存环与磁盘文件 |

策略为空时面板会给出解释：黑名单模式下说明「未禁止即放行」、当前不会拦截任何 SQL；
白名单模式下说明「未列出一律禁止」、当前所有 SQL 都会被拒，并明确这不是故障。
两种状态都附带示例写法与保存方式，避免用户误判插件没生效。

审计记录除「越权资源」外还保留 `matchedRules`（命中哪条策略）与
`inspectedTables`（本次检查了哪些表）——被拒的表和拒绝它的规则是两件事。

内存环保持最新 `audit.maxRecords` 条供即时读取；启用后同时追加到文件，重启后自动回填历史。
审计写入是 **fail-soft** 的：磁盘问题只损失历史，永不阻塞工具调用。

## 11. 防卸载与依赖机制

- 所有安全锁定**默认关闭**；默认状态下插件可随时卸载、无强制锁定、无启动强制依赖。
- `enableAntiUnmount` 打开后，`plugin_manager` 对本插件的停用/移除操作会被守卫拒绝，
  并提示先关闭该开关。它不改写 profile、不删除文件，是完全可解释、可撤销的硬化。
- `enableBundleRequireLock` 打开后，`requiredBundles` 中列出的 bundle 若未在本轮
  profile 中选中，插件激活即失败（fail loud）。
- 源码完全开放二次开发，可永久固化安全策略。

## 12. 开发与测试

```bash
npm test          # 或 pnpm test
```

- `tests/unit.mjs` — SQL 资源解析、策略引擎、远程客户端的 49 项断言
- `tests/engine.mjs` — 在真实 `apply()` 接线上的 28 项端到端断言（含审计路由与策略命中）
- `tests/report-vectors.mjs` — 第三方安全报告的 15 组向量（`DESCRIBE` / `SHOW` / 结构发现语义）

模块布局：

| 文件 | 职责 |
| --- | --- |
| `src/index.js` | 插件入口：Config、双引擎挂载、防卸载、审计接线与只读路由 |
| `src/client.js` | 浏览器半边：设置页只读面板（当前策略 + 最近拦截记录） |
| `src/sql-parse.js` | 基于 AST 的 SQL 资源提取（vendored `node-sql-parser`） |
| `vendor/node-sql-parser/` | 内联的 SQL 解析器（2.8 MB，见其 README） |
| `src/policy.js` | 权限决策引擎与远程 OpenAPI 客户端 |
| `src/audit.js` | 审计日志：内存环 + JSONL 追加写 |

## 13. 已知限制

- 客户端面板由 Host 启动时的模块图装配；**新增或改动 `src/client.js` 后需要重启
  dsh web 并刷新页面**才会生效（Cordis 的 HMR 不重新导入已缓存的 ESM 模块）。
- 严格守卫模式下，远程策略中台成为硬依赖：中台不可用时所有 SQL 调用都会被拒绝。
- 插件只识别 `targetToolPrefixes` 内的工具；若某个 MCP 数据库工具名不匹配，
  需自行补充前缀或打开 `includeNonMcpSqlTools`。

## 14. 许可证

MIT
