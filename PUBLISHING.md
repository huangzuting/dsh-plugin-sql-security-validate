# 发布前待办（TODO）

工程整改已完成，以下三项需要你本人确认后才能对外发布。每一项都涉及
真实主体信息，我不代填。

## 1. 填写版权人 —— `LICENSE`

```bash
# 当前内容
Copyright (c) 2026 [COPYRIGHT HOLDER]
```

把 `[COPYRIGHT HOLDER]` 替换为你的名字或组织名。
若涉及公司代码，通常填公司名而非个人名。

同时确认 `package.json` 的 `"author"` 与之对应：

```json
"author": "TODO: YOUR NAME <641694064@qq.com>"
```

## 2. 创建仓库并填写地址 —— `package.json` + `SECURITY.md` + `CHANGELOG.md`

三处含 `TODO` 占位符：

| 文件 | 字段 |
| --- | --- |
| `package.json` | `repository.url` / `homepage` / `bugs.url` |
| `SECURITY.md` | 私密漏洞报告链接 |
| `CHANGELOG.md` | 底部版本对比链接 |

建仓库时**不要**在命令行里贴密码。用下列任一方式：

```bash
# 方式一：Personal Access Token（推荐，最小权限：repo）
# 在 https://github.com/settings/tokens 生成，勾选 repo
git remote add origin https://<TOKEN>@github.com/<account>/dsh-plugin-sql-security-validate.git

# 方式二：SSH key（无需 token）
ssh-keygen -t ed25519 -C "641694064@qq.com"
# 把 ~/.ssh/id_ed25519.pub 内容贴到 https://github.com/settings/keys
git remote add origin git@github.com:<account>/dsh-plugin-sql-security-validate.git

git push -u origin main
```

推送后可检索确认没有遗漏：

```bash
grep -rn "TODO" --include="*.md" --include="*.json" .
```

## 3. 确认 npm 包名可用

```bash
npm view dsh-plugin-sql-security-validate
```

返回 404 说明名字可用；若已被占用，需要改 `package.json` 的 `name`，
同时改 `src/client.js` 中的路由常量（`AUDIT_ROUTE`）与
`vendor/README.md` 的引用。

## 完成后

```bash
pnpm install
npm test          # 期望 143 passed, 0 failed
npm pack --dry-run  # 期望 ~2.82 MB
```

`grep -rn "TODO"` 无输出即表示可以发布。
