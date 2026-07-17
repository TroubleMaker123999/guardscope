import { useEffect, useMemo, useRef, useState } from "react";
import { Search, X } from "lucide-react";
import type { BackendState, Finding } from "../types";
import { ALL_SEVERITIES, compareRisk, riskScore, SEVERITY_LABEL } from "../types";
import { CopyButton, Panel, SeverityPill, State, Tag } from "../components/ui";

interface Props {
  backend: {
    state: BackendState;
    findings: Finding[];
  };
}

export default function Findings({ backend }: Props) {
  const { findings, state } = backend;
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<string>("");
  const [source, setSource] = useState<string>("");
  const [selected, setSelected] = useState<Finding | null>(null);
  const rowRefs = useRef<Record<string, HTMLButtonElement | null>>({});

  const sources = useMemo(() => {
    const set = new Set(findings.map((f) => f.source));
    return Array.from(set).sort();
  }, [findings]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return [...findings]
      .filter((f) => (sev ? f.severity === sev : true))
      .filter((f) => (source ? f.source === source : true))
      .filter((f) => {
        if (!needle) return true;
        return [
          f.title,
          f.description,
          f.asset,
          f.evidence,
          f.remediation,
          f.source,
          ...f.cwe,
          ...f.owasp,
        ]
          .join("\n")
          .toLowerCase()
          .includes(needle);
      })
      .sort(compareRisk);
  }, [findings, q, sev, source]);

  function closeDrawer() {
    if (!selected) return;
    const id = selected.id;
    setSelected(null);
    window.requestAnimationFrame(() => rowRefs.current[id]?.focus());
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1>漏洞发现</h1>
          <div className="page-sub">
            共 {findings.length} 条；当前筛选命中 {filtered.length} 条，按风险评分排序。
          </div>
        </div>
      </div>

      <Panel flush>
        <div className="filter-bar">
          <span className="filter-label">
            <Search size={12} aria-hidden="true" /> 搜索
          </span>
          <input
            type="search"
            placeholder="标题、资产、证据、CWE…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            aria-label="搜索漏洞"
          />
          <select value={sev} onChange={(e) => setSev(e.target.value)} aria-label="按严重级筛选">
            <option value="">全部严重级</option>
            {ALL_SEVERITIES.map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
          </select>
          <select value={source} onChange={(e) => setSource(e.target.value)} aria-label="按来源筛选">
            <option value="">全部来源</option>
            {sources.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          {(q || sev || source) && (
            <button
              type="button"
              className="btn is-sm is-ghost"
              onClick={() => {
                setQ("");
                setSev("");
                setSource("");
              }}
            >
              <X size={12} aria-hidden="true" /> 重置
            </button>
          )}
        </div>

        <div className="list-head" role="row">
          <div>严重级</div>
          <div>标题</div>
          <div>来源</div>
          <div>资产</div>
          <div className="cell-score">风险</div>
        </div>

        {filtered.length === 0 ? (
          <State
            title="没有匹配的漏洞"
            detail={findings.length === 0 ? "导入一份扫描报告即可在此查看数据。" : "调整一下搜索条件或筛选器。"}
          />
        ) : (
          filtered.map((f) => (
            <button
              type="button"
              key={f.id}
              ref={(node) => {
                rowRefs.current[f.id] = node;
              }}
              className={`list-row${selected?.id === f.id ? " is-selected" : ""}`}
              onClick={() => setSelected(f)}
              aria-label={`打开漏洞：${f.title}`}
            >
              <SeverityPill severity={f.severity} />
              <div className="cell-title">{f.title}</div>
              <div className="cell-source">{f.source}</div>
              <div className="cell-asset">{f.asset || "—"}</div>
              <div className="cell-score">{riskScore(f).toFixed(1)}</div>
            </button>
          ))
        )}
      </Panel>

      {selected ? (
        <FindingDrawer finding={selected} demo={state.demo} onClose={closeDrawer} />
      ) : null}
    </>
  );
}

function FindingDrawer({
  finding,
  demo,
  onClose,
}: {
  finding: Finding;
  demo: boolean;
  onClose: () => void;
}) {
  const score = riskScore(finding);
  const dialogRef = useRef<HTMLElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    closeRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab" || !dialogRef.current) return;
      const focusable = Array.from(
        dialogRef.current.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
        ),
      ).filter((element) => !element.hasAttribute("disabled"));
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  return (
    <>
      <div className="drawer-backdrop" role="presentation" aria-hidden="true" onClick={onClose} />
      <aside
        ref={dialogRef}
        className="drawer"
        role="dialog"
        aria-modal="true"
        aria-label={`漏洞详情：${finding.title}`}
      >
        <header className="drawer-header">
          <div className="drawer-title">
            <h2>{finding.title}</h2>
            <div className="row">
              <SeverityPill severity={finding.severity} />
              <Tag>{finding.source}</Tag>
              <Tag>风险 {score.toFixed(2)}</Tag>
              {demo ? <Tag>演示数据</Tag> : null}
            </div>
          </div>
          <button
            ref={closeRef}
            type="button"
            className="btn is-sm is-ghost"
            onClick={onClose}
            aria-label="关闭详情面板"
          >
            <X size={14} aria-hidden="true" />
          </button>
        </header>

        <div className="drawer-body">
          <section className="drawer-section">
            <h3>漏洞描述</h3>
            <p>{finding.description || "—"}</p>
          </section>

          <section className="drawer-section">
            <h3>元数据</h3>
            <dl className="kv">
              <dt>资产</dt>
              <dd>
                {finding.asset || "—"}
                {finding.asset ? <CopyButton value={finding.asset} label="复制资产" /> : null}
              </dd>
              <dt>CVSS 评分</dt>
              <dd>{Number(finding.cvss || 0).toFixed(1)}</dd>
              <dt>置信度</dt>
              <dd>{finding.confidence}</dd>
              <dt>创建时间</dt>
              <dd>{finding.created_at}</dd>
              <dt>更新时间</dt>
              <dd>{finding.updated_at}</dd>
            </dl>
          </section>

          {finding.cwe.length || finding.owasp.length ? (
            <section className="drawer-section">
              <h3>分类标签</h3>
              <div className="row" style={{ flexWrap: "wrap", gap: 6 }}>
                {finding.cwe.map((c) => <Tag key={`cwe-${c}`}>{c}</Tag>)}
                {finding.owasp.map((o) => <Tag key={`owasp-${o}`}>{o}</Tag>)}
              </div>
            </section>
          ) : null}

          {finding.evidence ? (
            <section className="drawer-section">
              <h3>证据</h3>
              {demo ? <div className="alert is-warn small">演示数据的证据——非真实漏洞。</div> : null}
              <pre>{finding.evidence}</pre>
            </section>
          ) : null}

          {finding.remediation ? (
            <section className="drawer-section">
              <h3>修复建议</h3>
              <p>{finding.remediation}</p>
            </section>
          ) : null}

          <section className="drawer-section">
            <h3>指纹</h3>
            <div className="row">
              <code className="mono">{finding.fingerprint}</code>
              <CopyButton value={finding.fingerprint} label="复制指纹" />
            </div>
          </section>
        </div>
      </aside>
    </>
  );
}
