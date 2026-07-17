import type { Finding } from "../types";

/**
 * 本地兜底漏洞数据——在后端不可达时使用。
 *
 * 这些数据与 `guardscope/data/demo_findings.json` 保持同构，无论是否连到
 * API，界面上展示的字段形状都一致。Demo 模式会被显式标注，绝不会被
 * 误显示为"实时数据"。
 */
const NOW = new Date().toISOString();

function makeFinding(input: Omit<Finding, "duplicate_count">): Finding {
  return { ...input, duplicate_count: 1 };
}

export const DEMO_FINDINGS: Finding[] = [
  makeFinding({
    id: "demo-1",
    fingerprint: "demo-fp-1",
    title: "本地 nginx 演示镜像 OpenSSL 版本过旧",
    description:
      "本地 nginx 演示镜像内置 OpenSSL 3.0.x，存在一处已知低危漏洞。请将实验靶场升级到 3.0 系列最新补丁版本。",
    severity: "low",
    confidence: "high",
    cvss: 3.7,
    cwe: ["CWE-310"],
    owasp: ["A02:2021"],
    source: "trivy",
    asset: "guardscope-demo-lab:nginx@1.27-alpine",
    evidence: "OpenSSL 3.0.x < 3.0.13",
    remediation: "重建演示镜像，使用最新的 nginx:1.27-alpine 标签。",
    created_at: NOW,
    updated_at: NOW,
  }),
  makeFinding({
    id: "demo-2",
    fingerprint: "demo-fp-2",
    title: "首页响应缺少 Content-Security-Policy 头",
    description:
      "本地演示靶场在根路径响应中未返回 Content-Security-Policy 头，属于纵深防御层面的缺口。",
    severity: "medium",
    confidence: "medium",
    cvss: 5.3,
    cwe: ["CWE-693"],
    owasp: ["A05:2021"],
    source: "zap",
    asset: "http://127.0.0.1:8080/",
    evidence: "响应头中未发现 'content-security-policy'。",
    remediation: "在演示用 nginx 配置中添加一条严格的 CSP。",
    created_at: NOW,
    updated_at: NOW,
  }),
  makeFinding({
    id: "demo-3",
    fingerprint: "demo-fp-3",
    title: "演示应用中存在硬编码密码",
    description: "Bandit 在演示应用的配置加载器里标记了一处硬编码密码字符串。",
    severity: "high",
    confidence: "high",
    cvss: 7.5,
    cwe: ["CWE-798"],
    owasp: ["A07:2021"],
    source: "bandit",
    asset: "demo_app/config.py:12",
    evidence: "password = 'hunter2'",
    remediation: "从环境变量或密钥管理服务读取敏感凭据，切勿写入源码。",
    created_at: NOW,
    updated_at: NOW,
  }),
  makeFinding({
    id: "demo-4",
    fingerprint: "demo-fp-4",
    title: "面向用户的辅助函数中使用了 eval()",
    description:
      "Semgrep 规则 python.lang.security.audit.eval 在演示应用中命中了一处 eval() 调用。",
    severity: "high",
    confidence: "high",
    cvss: 7.0,
    cwe: ["CWE-95"],
    owasp: ["A03:2021"],
    source: "semgrep",
    asset: "demo_app/helpers.py:42",
    evidence: "eval(user_input)",
    remediation: "用安全的解析器替代 eval()；永远不要对不可信输入执行求值。",
    created_at: NOW,
    updated_at: NOW,
  }),
  makeFinding({
    id: "demo-5",
    fingerprint: "demo-fp-5",
    title: "扫描发现对外开放 SSH 服务指纹",
    description: "Nmap 在本地靶场扫描中观察到 22/TCP 端口上有 SSH 服务横幅。",
    severity: "info",
    confidence: "high",
    cvss: 0.0,
    cwe: [],
    owasp: [],
    source: "nmap",
    asset: "127.0.0.1:22/tcp",
    evidence: "127.0.0.1:22/tcp open ssh OpenSSH 9.6p1",
    remediation: "确认确实需要该 SSH 服务，并限制允许连接的来源地址。",
    created_at: NOW,
    updated_at: NOW,
  }),
  makeFinding({
    id: "demo-6",
    fingerprint: "demo-fp-6",
    title: "存在漏洞依赖：requests < 2.31.0",
    description: "pip-audit 在本地靶场固定的 requests 包版本上报告了 PYSEC-2023-74。",
    severity: "medium",
    confidence: "high",
    cvss: 6.1,
    cwe: ["CWE-20"],
    owasp: ["A06:2021"],
    source: "pip-audit",
    asset: "requests@2.20.0",
    evidence: "PYSEC-2023-74 aliases=CVE-2023-32681 fix=2.31.0",
    remediation: "将 requests 升级到 >=2.31.0。",
    created_at: NOW,
    updated_at: NOW,
  }),
  makeFinding({
    id: "demo-7",
    fingerprint: "demo-fp-7",
    title: "Cookie 缺少 Secure 属性",
    description: "本地靶场设置的会话 Cookie 缺少 Secure 属性。",
    severity: "low",
    confidence: "high",
    cvss: 3.1,
    cwe: ["CWE-614"],
    owasp: ["A05:2021"],
    source: "zap",
    asset: "http://127.0.0.1:8080/login",
    evidence: "Set-Cookie: session=...; HttpOnly",
    remediation: "为靶场下发的所有会话 Cookie 增加 Secure 属性。",
    created_at: NOW,
    updated_at: NOW,
  }),
];
