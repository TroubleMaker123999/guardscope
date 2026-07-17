# GuardScope · 安全运营控制台

> **Defense-oriented, authorization-scoped vulnerability management** — 防御向、授权范围内的漏洞接入与报告平台。

[![License](https://img.shields.io/github/license/TroubleMaker123999/guardscope?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12-blue?style=flat-square)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=white)](https://react.dev/)
[![Tests](https://img.shields.io/badge/tests-120%20passed-brightgreen?style=flat-square)]()
[![CI](https://img.shields.io/badge/CI-see%20Actions-lightgrey?style=flat-square)](../../actions)

GuardScope 把 **Nmap / OWASP ZAP / SARIF 2.1 / Bandit / Semgrep / Trivy / pip-audit** 七种扫描器输出归一化成一种内部数据模型，并提供去重、风险评分，以及 Markdown / HTML / JSON / SARIF 四种报告导出。

一个 React + TypeScript 控制台把所有东西聚到一个密度的安全运营面板里（仪表盘、漏洞列表、本地实验靶场、报告导入/下载、可选的漏洞测试视图），并显式标注"演示数据 / 实时数据"边界。

| | |
|---|---|
| ![Dashboard](docs/screenshot-dashboard.png) | ![Findings](docs/screenshot-findings.png) |
| **仪表盘**：4 个 KPI 卡 + 高风险 Top 列表 + 严重级分布 + 靶场范围 | **漏洞发现**：可筛选 / 搜索 / 风险排序，详情抽屉 |

---

## ✨ 功能

- **FastAPI + Typer CLI** — 接收扫描器输出、归一化、去重、评分、出报告。
- **7 种真实解析器**（stdlib XML / JSON，无外部依赖）：
  - Nmap XML、OWASP ZAP JSON、SARIF 2.1.0、Bandit JSON、Semgrep JSON、Trivy JSON、pip-audit JSON。
- **风险评分 + 指纹去重** — 同样的漏洞不会被算两遍。
- **4 种报告**：Markdown / HTML / JSON / SARIF。
- **本地实验靶场注册表 + 范围守卫** — 验证目标只允许 `127.0.0.1 / ::1 / localhost`。
- **React + TypeScript 安全运营控制台** — 5 个视图：仪表盘 / 漏洞 / 靶场 / 导入 / 可选的漏洞测试。
- **pytest 后端测试套件**（120 条全过）+ **GitHub Actions CI**（pytest + 前端 build）。

可选的 `offensive/` 子包把 Nmap / Hydra / sqlmap / Nuclei 封装在**硬范围守卫**后面，专门用于本地实验靶场 —— 详见下文。

---

## 🚀 30 秒快速上手

```bash
# 1. 装后端
python3.12 -m venv .venv
. .venv/bin/activate
pip install -e .

# 2. 装前端
cd frontend && npm install && cd ..

# 3. 起演示数据
guardscope demo --db ./guardscope.db

# 4. 起后端（一个终端）
guardscope serve --db ./guardscope.db --host 127.0.0.1 --port 8000

# 5. 起前端（另一个终端）
cd frontend && npm run dev    # → http://127.0.0.1:5173/
```

打开浏览器 `http://127.0.0.1:5173/` 看仪表盘，4 个 KPI + Top 发现 + 严重级分布。

---

## 🛡️ 安全边界（必读）

GuardScope 是个**防御**平台。它**不会**：
- ❌ 主动扫描公网或第三方主机
- ❌ 暴力破解、生成 exploit payload、绕过认证、留后门
- ❌ 自动向漏洞平台（edusrc 等）提交报告
- ❌ 把未授权主机暴露给任何工具

可选的 `offensive/` 子包对工具调用 **强制** 三层校验：

1. **回环地址**（127.0.0.0/8 / ::1 / localhost）
2. **lab 白名单** —— 目标必须先用 `guardscope labs register` 注册
3. **速率限制** —— 每个 action 60 秒内最多 30 次

任何 HTTP 路径、CLI flag、旁路脚本都无法跳过守卫。Hydra 默认拒绝 `rockyou.txt`，sqlmap 默认拒绝 `--os-shell / --file-write / --bind`，Nmap 默认拒绝 stealth 扫描模式（`-sS / -sF / -sX / -Pn`）。

完整安全边界见 `LEGAL.md`。

---

## 🧪 测试

```bash
./.venv/bin/python -m pytest -q          # 120 条
cd frontend && npm run typecheck         # 0 错误
cd frontend && npm run build             # dist/ 出来
./scripts/smoke.sh                        # 前端冒烟
```

CI：每次 push 跑 pytest + 前端 build。状态徽章见仓库首页。

---

## 🧱 项目结构

```
guardscope/
├── guardscope/            # 防御向 Python 包（parsers, reporting, api, lab, plugins, core）
├── frontend/              # React + TypeScript + Vite 控制台
├── offensive/              # 可选：本地实验靶场攻击工具封装（硬范围守卫）
│   ├── scope_guard.py
│   ├── audit.py
│   ├── nmap_runner.py / hydra_runner.py / sqlmap_runner.py / nuclei_runner.py
│   ├── api.py              # FastAPI 端点
│   └── lab_targets/        # compose 文件 + 寄存器脚本（loopback only）
├── tests/                  # pytest 套件（默认 72 + offensive 38 + api 10）
├── docs/                   # architecture.md + frontend.md
├── .github/workflows/      # CI：pytest + frontend ci/build/smoke
├── LICENSE                 # MIT
├── README.md                # 英文版
├── README_CN.md             # 你正在看的
└── LEGAL.md                 # 安全边界
```

---

## 🤝 贡献

PR 欢迎。请在 LICENSE 协议下开发。提交前跑 `pytest` + 前端 `build`；CI 会自动验证。

## 📜 许可证

[MIT](LICENSE) + 见 `LEGAL.md` 中的安全约束。