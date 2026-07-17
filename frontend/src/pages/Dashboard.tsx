import { useMemo } from "react";
import {
  AlertCircle,
  FlaskConical,
  Layers,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import type { BackendState, Finding, Lab } from "../types";
import { Panel, SeverityPill, State } from "../components/ui";
import { compareRisk, riskScore } from "../types";

interface Props {
  backend: {
    state: BackendState;
    findings: Finding[];
    labs: Lab[];
    refresh: () => Promise<void>;
  };
  onNavigate: (id: "dashboard" | "findings" | "labs" | "import") => void;
}

export default function Dashboard({ backend, onNavigate }: Props) {
  const { findings, labs, state } = backend;

  const kpis = useMemo(() => buildKpis(findings, labs), [findings, labs]);
  const sevDistribution = useMemo(() => buildDistribution(findings), [findings]);
  const topFindings = useMemo(() => [...findings].sort(compareRisk).slice(0, 6), [findings]);

  return (
    <>
      <div className="page-header">
        <div>
          <h1>仪表盘</h1>
          <div className="page-sub">
            归一化后的漏洞快照、严重级分布、以及已注册的本地实验靶场。
          </div>
        </div>
        <div className="page-actions">
          <button type="button" className="btn" onClick={() => onNavigate("findings")}>
            查看漏洞发现
          </button>
          <button type="button" className="btn is-primary" onClick={() => onNavigate("import")}>
            导入扫描报告
          </button>
        </div>
      </div>

      <div className="kpi-grid">
        <Kpi
          icon={<Layers size={14} aria-hidden="true" />}
          label="漏洞总数"
          value={kpis.total}
          sub={`来自 ${kpis.sources} 个扫描器`}
          tone="default"
        />
        <Kpi
          icon={<AlertCircle size={14} aria-hidden="true" />}
          label="严重 + 高危"
          value={kpis.criticalHigh}
          sub="需要立即处理"
          tone="bad"
        />
        <Kpi
          icon={<TriangleAlert size={14} aria-hidden="true" />}
          label="中危"
          value={kpis.medium}
          sub="本轮待评估"
          tone="warn"
        />
        <Kpi
          icon={<ShieldCheck size={14} aria-hidden="true" />}
          label="本地实验靶场"
          value={kpis.localLabs}
          sub={`已注册 ${labs.length} 个`}
          tone="ok"
        />
      </div>

      <div className="grid-2">
        <Panel
          title="高风险 Top 发现"
          actions={
            <button type="button" className="btn is-sm is-ghost" onClick={() => onNavigate("findings")}>
              查看全部
            </button>
          }
        >
          {topFindings.length === 0 ? (
            <State title="暂无漏洞数据" detail="导入一份扫描报告即可在仪表盘看到结果。" />
          ) : (
            <div>
              {topFindings.map((f) => (
                <button
                  type="button"
                  key={f.id}
                  className="list-row"
                  style={{
                    width: "100%",
                    background: "transparent",
                    border: "none",
                    textAlign: "left",
                  }}
                  onClick={() => onNavigate("findings")}
                  aria-label={`打开漏洞：${f.title}`}
                >
                  <SeverityPill severity={f.severity} />
                  <div className="cell-title">{f.title}</div>
                  <div className="cell-source">{f.source}</div>
                  <div className="cell-asset">{f.asset || "—"}</div>
                  <div className="cell-score">{riskScore(f).toFixed(1)}</div>
                </button>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="严重级分布">
          {findings.length === 0 ? (
            <State title="暂无严重级数据" />
          ) : (
            <div>
              {sevDistribution.map((row) => (
                <div key={row.key} className={`sev-row sev-${row.key}`}>
                  <div className="sev-label">{row.label}</div>
                  <div className="sev-bar-track">
                    <div className="sev-bar" style={{ width: `${row.pct}%` }} />
                  </div>
                  <div className="sev-count">{row.count}</div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      <div style={{ height: 16 }} />

      <Panel
        title="本地实验靶场范围"
        actions={
          <button type="button" className="btn is-sm is-ghost" onClick={() => onNavigate("labs")}>
            管理靶场
          </button>
        }
      >
        <div className="row" style={{ marginBottom: 12 }}>
          <span className="scope-badge">
            <FlaskConical size={12} aria-hidden="true" /> 仅回环地址
          </span>
          <span className="muted small">
            GuardScope 拒绝任何非 localhost / 127.0.0.1 / ::1 的主机作为验证目标。
          </span>
        </div>
        {labs.length === 0 ? (
          <State
            title="尚未注册靶场"
            detail={
              state.online
                ? "注册一个回环实验靶场，以便启用经范围校验的验证流程。"
                : "后端离线时，演示靶场会显示在下方。"
            }
          />
        ) : (
          <div style={{ display: "grid", gap: 12 }}>
            {labs.map((lab) => (
              <div key={lab.id} className="lab-card">
                <div>
                  <div className="lab-host">
                    {lab.host}:{lab.port}
                  </div>
                  <div className="lab-meta">{lab.name}</div>
                  {lab.description ? (
                    <div className="lab-description">{lab.description}</div>
                  ) : null}
                </div>
                <span className="scope-badge">在范围内</span>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </>
  );
}

function Kpi({
  icon,
  label,
  value,
  sub,
  tone,
}: {
  icon: JSX.Element;
  label: string;
  value: number;
  sub: string;
  tone: "default" | "bad" | "warn" | "ok";
}) {
  const cls = `kpi${tone === "default" ? "" : ` is-${tone}`}`;
  return (
    <div className={cls}>
      <div className="kpi-label">
        {icon}
        {label}
      </div>
      <div className="kpi-value tabular">{value}</div>
      <div className="kpi-sub">{sub}</div>
    </div>
  );
}

function buildKpis(findings: Finding[], labs: Lab[]) {
  const sources = new Set(findings.map((f) => f.source)).size;
  return {
    total: findings.length,
    sources,
    criticalHigh: findings.filter(
      (f) => f.severity === "critical" || f.severity === "high",
    ).length,
    medium: findings.filter((f) => f.severity === "medium").length,
    localLabs: labs.length,
  };
}

function buildDistribution(findings: Finding[]) {
  const order = ["critical", "high", "medium", "low", "info", "unknown"] as const;
  const labels: Record<string, string> = {
    critical: "严重",
    high: "高危",
    medium: "中危",
    low: "低危",
    info: "信息",
    unknown: "未知",
  };
  const counts: Record<string, number> = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const total = findings.length || 1;
  return order.map((key) => {
    const count = counts[key] || 0;
    return {
      key,
      label: labels[key],
      count,
      pct: Math.max(2, Math.round((count / total) * 100)),
    };
  });
}