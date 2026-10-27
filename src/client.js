window.__ModuleLoader__.load({
  id: 'dsh-plugin-sql-security-validate',
  factory: (require) => {
    var module = { exports: {} }
    var exports = module.exports
    Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' })

    const react = require('react')
    const h = react.createElement
    const { useState, useEffect, useCallback, Fragment } = react

    /** 与宿主侧 AUDIT_ROUTE 保持一致。 */
    const AUDIT_ROUTE = '/plugins/dsh-plugin-sql-security-validate/audit'

    /** 配置命名空间，等于 profile 里的行 id。 */
    const NAMESPACE = 'sql-security-validate'

    // ── 样式：只用继承色与透明度，跟随宿主明暗主题 ────────────────────────
    const label = { margin: 0, fontSize: '13px', opacity: 0.65 }
    const value = { margin: '2px 0 0', fontSize: '15px', fontVariantNumeric: 'tabular-nums' }
    const card = {
      border: '1px solid rgba(127,127,127,0.28)',
      borderRadius: '10px',
      padding: '12px 14px',
      marginBottom: '12px',
    }
    const table = { width: '100%', borderCollapse: 'collapse', fontSize: '12.5px' }
    const th = {
      textAlign: 'left', fontWeight: 600, opacity: 0.6, padding: '6px 8px',
      borderBottom: '1px solid rgba(127,127,127,0.25)', whiteSpace: 'nowrap',
    }
    const td = {
      padding: '6px 8px', borderBottom: '1px solid rgba(127,127,127,0.12)', verticalAlign: 'top',
    }
    const button = {
      font: 'inherit', fontSize: '12.5px', padding: '4px 12px', borderRadius: '7px',
      border: '1px solid rgba(127,127,127,0.35)', background: 'transparent',
      color: 'inherit', cursor: 'pointer',
    }
    const buttonPrimary = {
      ...button, background: 'rgba(127,127,127,0.16)', fontWeight: 600,
    }
    const input = {
      font: 'inherit', fontSize: '12.5px', padding: '5px 8px', borderRadius: '7px',
      border: '1px solid rgba(127,127,127,0.35)', background: 'transparent',
      color: 'inherit', width: '100%', boxSizing: 'border-box',
    }
    const textarea = { ...input, minHeight: '68px', resize: 'vertical', lineHeight: 1.5 }
    const row = { display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }
    const rowBetween = { ...row, justifyContent: 'space-between' }
    const hint = { margin: '4px 0 0', fontSize: '12px', opacity: 0.5 }
    const codeStyle = {
      padding: '1px 5px', borderRadius: '4px', background: 'rgba(127,127,127,0.16)',
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: '11.5px',
    }

    /**
     * 把一条审计记录译成可读的原因。
     * @param {object} record 宿主返回的记录。
     * @returns {string} 展示文本。
     */
    function reasonOf(record) {
      const parts = []
      if (Array.isArray(record.forbiddenTables) && record.forbiddenTables.length > 0) {
        parts.push('表 ' + record.forbiddenTables.join('、'))
      }
      if (Array.isArray(record.forbiddenColumns) && record.forbiddenColumns.length > 0) {
        parts.push('字段 ' + record.forbiddenColumns.join('、'))
      }
      return parts.length > 0 ? parts.join('；') : (record.reason || '—')
    }

    /**
     * 时间戳转本地时间。
     * @param {number} time 毫秒时间戳。
     * @returns {string} 展示文本。
     */
    function timeOf(time) {
      const date = new Date(time)
      if (Number.isNaN(date.getTime())) return '—'
      const pad = n => String(n).padStart(2, '0')
      return pad(date.getMonth() + 1) + '-' + pad(date.getDate())
        + ' ' + pad(date.getHours()) + ':' + pad(date.getMinutes()) + ':' + pad(date.getSeconds())
    }

    /**
     * 把策略文本域解析成条目数组：一行一条，忽略空行与 # 注释。
     * @param {string} text 文本域内容。
     * @returns {string[]} 条目。
     */
    function parseEntries(text) {
      return String(text)
        .split('\n')
        .map(line => line.trim())
        .filter(line => line !== '' && !line.startsWith('#'))
    }

    /**
     * 一条策略行的行内编辑区。
     * @param {object} props 标题、说明、当前值、保存回调。
     * @returns {object} React 元素。
     */
    function PolicyEditor(props) {
      const { title, description, entries, placeholder, onSave, busy } = props
      const joined = entries.join('\n')
      const [text, setText] = useState(joined)
      const [dirty, setDirty] = useState(false)

      // 宿主值变化时（含保存成功后回读）同步，但不要覆盖用户正在输入的内容。
      useEffect(() => {
        if (!dirty) setText(joined)
      }, [joined, dirty])

      return h('div', { style: { marginBottom: '14px' } },
        h('p', { style: { margin: '0 0 4px', fontSize: '13px', fontWeight: 600 } }, title),
        h('p', { style: { ...hint, margin: '0 0 6px' } }, description),
        h('textarea', {
          style: textarea,
          value: text,
          spellCheck: false,
          placeholder,
          onChange: event => { setDirty(true); setText(event.target.value) },
        }),
        h('div', { style: { ...row, marginTop: '6px', marginBottom: 0 } },
          h('button', {
            type: 'button',
            style: buttonPrimary,
            disabled: busy,
            onClick: async () => {
              const ok = await onSave(parseEntries(text))
              if (ok) setDirty(false)
            },
          }, busy ? '保存中…' : '保存'),
          h('button', {
            type: 'button',
            style: button,
            disabled: busy || !dirty,
            onClick: () => { setText(joined); setDirty(false) },
          }, '撤销'),
          dirty ? h('span', { style: hint }, '未保存') : null,
        ),
      )
    }

    /** 可折叠的审计记录详情。 */
    function RecordDetail(props) {
      const record = props.record
      const field = (name, content) => h('div', { style: { marginBottom: '8px' } },
        h('p', { style: { ...label, margin: '0 0 2px' } }, name),
        h('p', { style: { margin: 0, fontSize: '12.5px', lineHeight: 1.6 } }, content),
      )
      return h('div', {
        style: {
          padding: '10px 12px', background: 'rgba(127,127,127,0.08)',
          borderRadius: '8px', margin: '4px 0 8px',
        },
      },
      field('原始 SQL', h('code', {
        style: {
          display: 'block', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
          fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: '12px',
        },
      }, record.sql || '—')),
      field('命中策略',
        Array.isArray(record.matchedRules) && record.matchedRules.length > 0
          ? h('span', null, record.matchedRules.map((rule, index) => h('code', {
            key: rule,
            style: {
              display: 'inline-block', padding: '1px 6px', marginRight: '6px',
              borderRadius: '5px', background: 'rgba(127,127,127,0.16)', fontSize: '12px',
            },
          }, rule)))
          : '—'),
      field('检查到的表',
        Array.isArray(record.inspectedTables) && record.inspectedTables.length > 0
          ? record.inspectedTables.join('、') : '—'),
      field('权限来源 / 引擎',
        (record.policySource || '—') + ' / ' + (record.interceptMode || '—')),
      field('会话', record.sessionId || '—'),
      record.reason ? field('拒绝原因', record.reason) : null,
      )
    }

    /**
     * 设置页里的操作面板：开关、模式、策略编辑、审计详情。
     * @param {object} props 设置页注入的 section 属性。
     * @returns {object} React 元素。
     */
    function SqlSecuritySection(props) {
      const [state, setState] = useState({ status: 'loading', data: null, error: '' })
      const [busy, setBusy] = useState(false)
      const [openSeq, setOpenSeq] = useState(null)
      const [notice, setNotice] = useState('')

      /** 读取宿主快照与审计。 */
      const load = useCallback(async () => {
        try {
          const response = await fetch(AUDIT_ROUTE, {
            credentials: 'same-origin',
            headers: { accept: 'application/json' },
          })
          if (!response.ok) throw new Error('HTTP ' + response.status)
          const data = await response.json()
          setState({ status: 'ready', data, error: '' })
        } catch (error) {
          setState({ status: 'error', data: null, error: String((error && error.message) || error) })
        }
      }, [])

      useEffect(() => { void load() }, [load])

      /**
       * 通过 settings 表单写入一项配置，然后回读宿主快照。
       * @param {string} field 字段名。
       * @param {unknown} next 新值。
       * @returns {Promise<boolean>} 是否写入成功。
       */
      const writeConfig = useCallback(async (field, next) => {
        const form = props.configForm
        if (form === undefined || form === null) {
          setNotice('当前环境没有配置写入通道，请到「插件」页修改配置。')
          return false
        }
        setBusy(true)
        setNotice('')
        try {
          const ok = await form.set(field, next)
          if (!ok) setNotice('保存失败：配置被更新占用或写入被拒绝，请重试。')
          else setNotice('已保存')
          await load()
          return ok
        } catch (error) {
          setNotice('保存失败：' + String((error && error.message) || error))
          return false
        } finally {
          setBusy(false)
        }
      }, [props.configForm, load])

      /** 清空审计日志。 */
      const clearAudit = useCallback(async () => {
        setBusy(true)
        try {
          const response = await fetch(AUDIT_ROUTE, { method: 'DELETE', credentials: 'same-origin' })
          if (!response.ok) throw new Error('HTTP ' + response.status)
          setNotice('审计日志已清空')
          await load()
        } catch (error) {
          setNotice('清空失败：' + String((error && error.message) || error))
        } finally {
          setBusy(false)
        }
      }, [load])

      const data = state.data
      const records = data && Array.isArray(data.records) ? data.records : []
      const denied = records.filter(record => record.outcome === 'deny').length
      const allowed = records.length - denied

      const header = h('div', { style: { ...rowBetween, marginBottom: '12px' } },
        h('div', null,
          h('p', { style: { margin: 0, fontSize: '16px', fontWeight: 600 } }, 'SQL 权限校验'),
          h('p', { style: { margin: '4px 0 0', fontSize: '12.5px', opacity: 0.6 } },
            '拦截 Agent 发起的越权 SQL；拒绝时把结构化原因回给模型。'),
        ),
        h('div', { style: { display: 'flex', gap: '8px' } },
          h('button', { type: 'button', style: button, onClick: () => void load() }, '刷新')))

      if (state.status === 'loading' && data === null) {
        return h('div', null, header, h('p', { style: label }, '读取中…'))
      }
      if (state.status === 'error') {
        return h('div', null, header,
          h('div', { style: card },
            h('p', { style: { ...label, opacity: 0.8 } }, '无法读取宿主数据：' + state.error),
            h('p', { style: { ...label, marginTop: '6px' } }, '如果刚升级过插件，重启 dsh web 后再试。')))
      }

      const missingForm = props.configForm === undefined || props.configForm === null

      // ── 控制区 ──────────────────────────────────────────────────────────
      const controls = h('div', { style: { ...card } },
        h('p', { style: { margin: '0 0 10px', fontSize: '13px', fontWeight: 600 } }, '开关与模式'),
        h('div', { style: rowBetween },
          h('div', null,
            h('p', { style: label }, '总开关'),
            h('p', { style: hint }, data.enabled ? '拦截生效中' : '已停用，所有 SQL 直接放行'),
          ),
          h('button', {
            type: 'button',
            style: data.enabled ? button : buttonPrimary,
            disabled: busy || missingForm,
            onClick: () => void writeConfig('enable', !data.enabled),
          }, data.enabled ? '停用' : '启用'),
        ),
        h('div', { style: { ...rowBetween, marginBottom: 0 } },
          h('div', null,
            h('p', { style: label }, '权限模式'),
            h('p', { style: hint },
              data.securityMode === 'whitelist_emulate'
                ? '白名单模拟：仅放行「放行名单」里列出的资源'
                : '黑名单：策略未禁止即放行'),
          ),
          h('button', {
            type: 'button',
            style: button,
            disabled: busy || missingForm,
            onClick: () => void writeConfig(
              'securityMode',
              data.securityMode === 'whitelist_emulate' ? 'blacklist' : 'whitelist_emulate',
            ),
          }, '切换到' + (data.securityMode === 'whitelist_emulate' ? '黑名单' : '白名单')),
        ),
        h('div', { style: { ...rowBetween, marginTop: '10px', marginBottom: 0 } },
          h('div', null,
            h('p', { style: label }, '严格守卫'),
            h('p', { style: hint }, data.strictGuard
              ? '已开启：拒绝后任何插件都无法改回放行'
              : '未开启：走普通事件拦截'),
          ),
          h('button', {
            type: 'button',
            style: data.strictGuard ? button : button,
            disabled: busy || missingForm,
            onClick: () => void writeConfig('enableStrictGuardMode', !data.strictGuard),
          }, data.strictGuard ? '关闭' : '开启'),
        ),
      )

      // ── 策略编辑 ────────────────────────────────────────────────────────
      const policy = data.policy || {}
      const blacklistTables = policy.tables ?? []
      const blacklistColumns = policy.columns ?? []
      const whitelistTables = policy.grantedTables ?? []
      const whitelistColumns = policy.grantedColumns ?? []
      const remoteEnabled = policy.remoteEnabled === true

      /** 当前模式下的策略是否为空——空策略会让用户误以为「插件没生效」。 */
      const hasRules = data.securityMode === 'whitelist_emulate'
        ? whitelistTables.length > 0 || whitelistColumns.length > 0 || remoteEnabled
        : blacklistTables.length > 0 || blacklistColumns.length > 0 || remoteEnabled

      /**
       * 策略为空时的解释块：说明当前行为、后果，以及怎么加第一条策略。
       * @param {string} mode 当前权限模式。
       * @returns {object|null} React 元素。
       */
      const emptyNotice = target => target ? h('div', {
        style: {
          ...card,
          borderStyle: 'dashed',
          background: 'rgba(127,127,127,0.06)',
        },
      },
      h('p', { style: { margin: '0 0 6px', fontSize: '13px', fontWeight: 600 } },
        data.securityMode === 'whitelist_emulate'
          ? '还没有任何放行条目'
          : '还没有任何禁止条目'),
      h('p', { style: { ...hint, margin: '0 0 8px', lineHeight: 1.7 } },
        data.securityMode === 'whitelist_emulate'
          ? '白名单模式下「未列出的一律禁止」。现在没有任何放行条目，'
            + '所有 SQL 都会被拒绝——这是符合预期的拦截行为，不是故障。'
          : '黑名单模式下「未禁止的一律放行」。现在没有任何禁止条目，'
            + '插件不会拦截任何 SQL——它在工作，只是没有规则要执行。'),
      h('p', { style: { ...hint, margin: 0, lineHeight: 1.8 } },
        '添加第一条策略：在下方「' + (data.securityMode === 'whitelist_emulate' ? '放行名单' : '禁止名单')
        + '」文本域里每行写一条，然后点「保存」。',
        h('br'),
        '表写 ',
        h('code', { style: codeStyle }, 'db.table'),
        '（例如 ',
        h('code', { style: codeStyle }, 'demo.user'),
        '），字段写 ',
        h('code', { style: codeStyle }, 'db.table.column'),
        '（例如 ',
        h('code', { style: codeStyle }, 'demo.user.phone'),
        '）。',
        h('br'),
        '首位 ',
        h('code', { style: codeStyle }, 'db'),
        ' 是「任意库」占位符，',
        h('code', { style: codeStyle }, 'demo.user'),
        ' 和 ',
        h('code', { style: codeStyle }, 'user'),
        ' 都能命中同一个表。修改即时生效，无需重启。'),
      ) : null

      const editors = missingForm ? null : h('div', null,
        emptyNotice(hasRules === false),
        h('div', { style: card },
          h('p', { style: { margin: '0 0 4px', fontSize: '13px', fontWeight: 600 } },
            data.securityMode === 'whitelist_emulate' ? '放行名单（白名单）' : '禁止名单（黑名单）'),
          h('p', { style: { ...hint, margin: '0 0 10px' } },
            data.securityMode === 'whitelist_emulate'
              ? '只有这里列出的资源可以访问；其余一律拒绝。不需要权限中台。'
              : '这里列出的表与字段会被拒绝；其余放行。'),
          // A bare table name in a whitelist is ambiguous: `user` also covers
          // `mysql.user`, because a bare entry matches a qualified resource's
          // tail. Warn rather than silently widen the grant.
          data.securityMode === 'whitelist_emulate' && whitelistTables.some(entry => !entry.includes('.'))
            ? h('p', {
              style: {
                margin: '0 0 10px',
                fontSize: '12px',
                lineHeight: 1.6,
                color: '#b45309',
                background: '#fffbeb',
                border: '1px solid #fde68a',
                borderRadius: '6px',
                padding: '8px 10px',
              },
            }, '提示：名单里有不带库名的表名。'
              + '裸表名会匹配所有库下的同名表（例如 user 也会放行 mysql.user）。'
              + '若只授权某个库，请写成「库名.表名」。')
            : null,
          data.securityMode === 'whitelist_emulate'
            ? h(Fragment, null,
              h(PolicyEditor, {
                title: '允许访问的表',
                description: '例：demo.user、demo.orders。允许整表时只写表名即可。',
                entries: whitelistTables,
                placeholder: 'demo.user\ndemo.orders',
                busy,
                onSave: entries => writeConfig('localWhitelist', {
                  tables: entries,
                  columns: whitelistColumns,
                }),
              }),
              h(PolicyEditor, {
                title: '允许访问的字段',
                description: '仅在需要「按字段授权」时填写，例：demo.user_private.phone。',
                entries: whitelistColumns,
                placeholder: 'demo.user_private.phone',
                busy,
                onSave: entries => writeConfig('localWhitelist', {
                  tables: whitelistTables,
                  columns: entries,
                }),
              }))
            : h(Fragment, null,
              h(PolicyEditor, {
                title: '禁止访问的表',
                description: '例：db.admin、db.sensitive_log',
                entries: blacklistTables,
                placeholder: 'db.admin\ndb.sensitive_log',
                busy,
                onSave: entries => writeConfig('localBlacklist', {
                  tables: entries,
                  columns: blacklistColumns,
                }),
              }),
              h(PolicyEditor, {
                title: '禁止访问的字段',
                description: '例：db.user.phone、db.user.idcard',
                entries: blacklistColumns,
                placeholder: 'db.user.phone\ndb.user.idcard',
                busy,
                onSave: entries => writeConfig('localBlacklist', {
                  tables: blacklistTables,
                  columns: entries,
                }),
              })),
          remoteEnabled
            ? h('p', { style: { ...hint, margin: 0 } },
              '已开启远程权限中台，中台返回的条目会叠加在本地策略之上。')
            : null,
        ),
      )

      // ── 审计 ────────────────────────────────────────────────────────────
      const summary = h('div', { style: rowBetween },
        h('p', { style: { margin: 0, fontSize: '13px', fontWeight: 600 } },
          '拦截审计 · 最近 ' + records.length + ' 条（放行 ' + allowed + '，拒绝 ' + denied + '）'),
        h('div', { style: { display: 'flex', gap: '8px' } },
          h('button', {
            type: 'button', style: button, disabled: busy || records.length === 0,
            onClick: () => void clearAudit(),
          }, '清空'),
        ))

      const auditBody = records.length === 0
        ? h('p', { style: { ...label, padding: '14px 0' } },
          '还没有审计记录。等 Agent 发起一次 MCP 数据库调用后这里就会出现。')
        : h('div', { style: { overflowX: 'auto' } },
          h('table', { style: table },
            h('thead', null, h('tr', null,
              h('th', { style: th }, '时间'),
              h('th', { style: th }, '工具'),
              h('th', { style: th }, '结果'),
              h('th', { style: th }, '越权资源 / 命中'),
              h('th', { style: th }, ''),
            )),
            h('tbody', null, records.map(record => h(Fragment, { key: record.seq },
              h('tr', {
                style: { cursor: 'pointer' },
                onClick: () => setOpenSeq(openSeq === record.seq ? null : record.seq),
              },
              h('td', { style: { ...td, whiteSpace: 'nowrap', opacity: 0.7 } }, timeOf(record.time)),
              h('td', { style: td }, (record.toolName || '—').replace('mcp__dbx__', '')),
              h('td', {
                style: {
                  ...td, whiteSpace: 'nowrap', fontWeight: 600,
                  color: record.outcome === 'deny' ? 'inherit' : 'inherit',
                  opacity: record.outcome === 'deny' ? 1 : 0.7,
                },
              }, record.outcome === 'deny' ? '拒绝' : '放行'),
              h('td', { style: { ...td, opacity: 0.75 } }, reasonOf(record)),
              h('td', { style: { ...td, opacity: 0.5, whiteSpace: 'nowrap' } },
                openSeq === record.seq ? '收起' : '详情'),
              ),
              openSeq === record.seq ? h('tr', null,
                h('td', { colSpan: 5, style: { padding: '0 8px' } }, h(RecordDetail, { record }))) : null,
            ))),
          ))

      return h('div', null,
        header,
        notice !== '' ? h('p', {
          style: {
            margin: '0 0 10px', fontSize: '12.5px', padding: '7px 10px',
            borderRadius: '7px', background: 'rgba(127,127,127,0.12)',
          },
        }, notice) : null,
        controls,
        missingForm ? h('p', { style: hint },
          '当前环境没有配置写入通道，请到「插件」页修改策略；下面的审计仍然可用。') : null,
        editors,
        h('div', { style: card }, summary, auditBody),
        h('p', { style: { ...label, marginTop: '14px' } },
          '改动即时生效，无需重启。审计明细点击任意一行展开，可看到原始 SQL 与命中的具体策略条目。'),
      )
    }




    /**
     * 从插槽传入的 owner props 里取出轮次号。
     *
     * 宿主 `TurnTailOwnerProps.turn` 的类型是 `TurnLocation` —— 一个已解析的
     * 轮次边界对象（`{ turn, start, end, status, steps }`），真实编号在 `.turn`。
     * 这里同时接受裸数字，避免宿主换签名时又静默不渲染。
     *
     * @param value 插槽给的 turn 值。
     * @returns 轮次号；取不到时返回 -1。
     */
    function turnNumberOf(value) {
      if (typeof value === 'number') return Number.isInteger(value) ? value : -1
      if (value !== null && typeof value === 'object' && typeof value.turn === 'number') {
        return Number.isInteger(value.turn) ? value.turn : -1
      }
      return -1
    }

    /**
     * 一轮对话结束后的拦截卡片。
     *
     * SQL 拦截是「这一轮里发生的事」，所以记录挂在轮次尾部而不是全局浮层。
     * 折叠态只显示一行摘要（本轮被拦了几次、涉及哪些表），点开才展开 SQL
     * 与命中策略——避免每轮都堆一大块内容。
     *
     * @param {object} props 插槽 owner props，含 `turn`。
     * @returns {object|null} React 元素；本轮无记录时不渲染任何东西。
     */
    function TurnInterceptionCard(props) {
      // The slot hands over a `TurnLocation`, not a bare number: the resolved
      // boundary object carries the turn number at `.turn`. Accepting only a
      // number here silently rendered nothing on every turn.
      const turn = turnNumberOf(props.turn)
      const [open, setOpen] = useState(false)
      const [data, setData] = useState(null)
      const [error, setError] = useState('')

      const load = useCallback(async () => {
        if (typeof turn !== 'number' || turn < 0) return
        try {
          const response = await fetch(`${AUDIT_ROUTE}?turn=${encodeURIComponent(turn)}`, {
            credentials: 'same-origin',
            headers: { accept: 'application/json' },
          })
          if (!response.ok) throw new Error('HTTP ' + response.status)
          setData(await response.json())
          setError('')
        } catch (thrown) {
          setError(String((thrown && thrown.message) || thrown))
        }
      }, [turn])

      useEffect(() => { void load() }, [load])

      const records = data !== null && Array.isArray(data.records) ? data.records : []
      const denied = records.filter(record => record.outcome === 'deny').length
      // Nothing happened in this turn: contribute no row at all, so a turn
      // without database activity looks exactly as it did before installation.
      if (data !== null && records.length === 0) return null
      if (error !== '' || data === null) return null

      const tables = []
      for (const record of records) {
        for (const table of record.inspectedTables ?? []) {
          if (!tables.includes(table)) tables.push(table)
        }
      }

      const summary = denied > 0
        ? `本轮拦截 ${denied} 次 SQL`
        : `本轮 ${records.length} 次 SQL 全部放行`

      return h('div', {
        style: {
          margin: '8px 0 0',
          border: '1px solid rgba(127,127,127,0.24)',
          borderRadius: '9px',
          fontSize: '12.5px',
          overflow: 'hidden',
        },
      },
      h('button', {
        type: 'button',
        'aria-expanded': open ? 'true' : 'false',
        onClick: () => setOpen(!open),
        style: {
          display: 'flex', alignItems: 'center', gap: '8px', width: '100%',
          padding: '7px 11px', border: 'none', background: 'transparent',
          color: 'inherit', cursor: 'pointer', font: 'inherit', textAlign: 'left',
        },
      },
      // 盾牌小标：有拦截时实心，全部放行时描边。
      h('svg', {
        viewBox: '0 0 24 24', width: 14, height: 14, 'aria-hidden': 'true',
        fill: denied > 0 ? 'currentColor' : 'none',
        stroke: 'currentColor', strokeWidth: 1.8,
        strokeLinecap: 'round', strokeLinejoin: 'round',
        style: { flexShrink: 0, opacity: denied > 0 ? 0.9 : 0.5 },
      }, h('path', { d: 'M12 3l7 3v5.5c0 4.2-2.9 7.9-7 9.5-4.1-1.6-7-5.3-7-9.5V6l7-3z' })),
      h('span', { style: { fontWeight: 600, opacity: denied > 0 ? 1 : 0.65 } }, summary),
      tables.length > 0
        ? h('span', {
          style: {
            opacity: 0.5, fontSize: '11.5px', overflow: 'hidden',
            textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1,
          },
        }, tables.join('、'))
        : null,
      h('span', { style: { marginLeft: 'auto', opacity: 0.45, fontSize: '11.5px' } },
        open ? '收起' : '详情'),
      ),
      open ? h('div', {
        style: { padding: '0 11px 10px', borderTop: '1px solid rgba(127,127,127,0.14)' },
      },
      records.map(record => h('div', {
        key: record.seq,
        style: { padding: '7px 0', borderBottom: '1px solid rgba(127,127,127,0.1)' },
      },
      h('div', { style: { display: 'flex', justifyContent: 'space-between', gap: '8px' } },
        h('span', { style: { fontWeight: 600, opacity: record.outcome === 'deny' ? 1 : 0.6 } },
          record.outcome === 'deny' ? '拒绝' : '放行'),
        h('span', { style: { ...hint, margin: 0 } }, timeOf(record.time)),
      ),
      h('code', {
        style: {
          display: 'block', marginTop: '3px', fontSize: '11.5px', opacity: 0.8,
          whiteSpace: 'pre-wrap', wordBreak: 'break-all',
          fontFamily: 'ui-monospace, Menlo, monospace',
        },
      }, record.sql || '—'),
      Array.isArray(record.matchedRules) && record.matchedRules.length > 0
        ? h('p', { style: { ...hint, margin: '3px 0 0' } },
          '命中：' + record.matchedRules.join('、'))
        : null,
      )),
      ) : null,
      )
    }

    /**
     * 依赖的客户端服务：插槽注册表与配置表单。
     * configForms 是可选的：缺失时面板仍可读，只是不能改。
     */
    exports.inject = ['slots', 'configForms']

    /**
     * 把面板挂到设置页，并在输入区放一个盾牌入口。
     * @param {object} ctx 客户端上下文。
     */
    exports.apply = function apply(ctx) {
      const configForm = ctx.configForms.get(NAMESPACE)

      ctx.slots.inject('settings.section', () => ctx.slots.register({
        name: 'settings.section',
        id: 'sql-security-validate',
        order: 50,
        label: () => 'SQL 权限校验',
        inject: () => ({ configForm }),
      }, SqlSecuritySection))

      // Per-turn card: SQL interception is something that happened inside ONE
      // turn, so the record belongs under that turn rather than in a global
      // popover. The slot's owner props carry the turn number.
      ctx.slots.inject('conversation.chat.turnTail', () => ctx.slots.register({
        name: 'conversation.chat.turnTail',
        id: 'sql-security-turn',
        order: 40,
        label: () => 'SQL 权限校验',
      }, TurnInterceptionCard))
    }

    return module.exports
  },
})
