# 二次开发手册

## 1. 代码地图

```
src/index.js       插件入口：Config schema、双引擎挂载、防卸载、强依赖校验、审计接线
src/sql-parse.js   无依赖 SQL 资源提取：表、字段、JOIN、子查询、CTE、函数
src/policy.js      权限决策（黑名单 / 白名单模拟）+ 远程 OpenAPI 客户端与缓存
src/audit.js       审计日志：内存环 + $DSH_HOME JSONL 追加写
tests/unit.mjs     纯函数断言（30 项）
tests/engine.mjs   在真实 apply() 接线上的端到端断言（14 项）
```

四个模块都是纯 ESM，无构建步骤。除 `src/index.js` 需要 `@deepseek-ai/schemastery`
外，其余三个模块**零外部依赖**，可单独复用。

## 2. 扩展点

### 2.1 换一个资源提取器

`parseSql(sql)` 的契约：

```ts
{
  isSql: boolean            // 是否看起来像 SQL 语句
  statementKinds: string[]  // select / insert / update / ...
  mutating: boolean         // 是否含写操作
  tables: string[]          // 规范化后的 db.table
  columns: string[]         // 列引用原样（可含别名前缀）
}
```

`collectSqlCandidates(args, { keys, includeOthers })` 返回
`[{ sql, origin, parsed }]`。只要保持这两个契约，即可整体替换为真正的 AST 解析器
（例如接入 `node-sql-parser`）：

```js
// src/sql-parse.js
import { Parser } from 'node-sql-parser'
const parser = new Parser()

export function parseSql(sql) {
  try {
    const ast = parser.astify(sql, { database: 'mysql' })
    // …把 ast 映射成 { isSql, statementKinds, mutating, tables, columns }
    return mapped
  } catch {
    return { isSql: false, statementKinds: [], mutating: false, tables: [], columns: [] }
  }
}
```

**保持「解析失败即 isSql:false」的契约**——插件对非 SQL 字符串不做任何拦截，这条边界
是它不误伤普通工具调用的前提。

### 2.2 换一个策略后端

`RemotePolicyClient` 只要求一个 `read()` 方法返回：

```ts
{ forbiddenTables: string[], forbiddenColumns: string[],
  grantedTables: string[], grantedColumns: string[] }
```

替换 `buildPolicy()` 里的来源即可对接内部权限系统（LDAP / OPA / 自研网关）。
若新后端是**同步**可读的（例如本地缓存文件），可以直接在守卫里读它，
让严格模式不再依赖异步预取。

### 2.3 加一条自定义决策规则

`Policy.decide(parsed)` 是唯一判定入口。要加规则（例如「禁止跨库 JOIN」「禁止无 WHERE
的全表扫描」），在 `decide` 里追加判断，并在返回值里带上 `forbiddenTables` /
`forbiddenColumns`——审计与拒绝原因都从这两个字段生成，无需改别处。

### 2.4 加一个新的加固开关

1. 在 `Config` 里加**叶子** volatile 字段（schemastery 不允许 volatile 内嵌 volatile）。
2. 在 `snapshotOf()` 里用 `readField(config.x, 默认值)` 读出。
3. 在 `apply()` 里按开关决定挂不挂守卫 / 是否在激活时抛错。
4. 在 `locale/zh.json`、`locale/en.json` 的 `field.*` 下补文案。

## 3. 三条不能破的约束

1. **不要改 SQL。** 只拒绝，不改写。静默改写会让模型以为数据完整。
2. **默认不锁定。** 新开关一律默认关闭；默认状态下插件必须能零代价卸载。
3. **决策失败要 fail-closed。** 策略拿不到时拒绝，绝不「拿不到就当有权限」。

## 4. 本地调试

```bash
npm test

# 单独跑解析器
node -e "import('./src/sql-parse.js').then(m => console.log(m.parseSql('SELECT u.id FROM db.user u JOIN db.orders o ON o.uid = u.id')))"
```

在已安装的 profile 里热更新：直接改 `src/*.js` 后，**重启 Host 进程**才会加载新代码。
Cordis 的 HMR 不会重新导入已被缓存的 ESM 模块，因此改动后请先 `set_bundle` 停用再启用，
仍失败则重启进程。

## 5. 版本与兼容

- `package.json` 的 `dsh.bundle.patch` 指向 `cordis.patch.yml`；安装后 profile 里会出现
  一行 `id: sql-security-validate`。
- 修改 `Config` 时若删除字段，老 profile 里的同名字段会被 schemastery 忽略，
  不必写迁移。
- 审计记录 JSONL 是**只追加**的；新增字段对老读者安全，删除字段需要自增
  `AuditLog.accepts()` 的兼容判断。
