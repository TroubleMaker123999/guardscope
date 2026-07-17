import { useState } from "react";
import { Download, FileUp, ShieldCheck, TriangleAlert } from "lucide-react";
import { ApiError, getReportRaw, importReport } from "../lib/api";
import type { BackendState, ImportResult, ReportFormat } from "../types";
import { ALL_SOURCES } from "../types";
import { Panel, State } from "../components/ui";

interface Props {
  backend: {
    state: BackendState;
    refresh: () => Promise<void>;
  };
}

const FORMATS: ReportFormat[] = ["markdown", "html", "json", "sarif"];

const FORMAT_LABELS: Record<ReportFormat, string> = {
  markdown: "Markdown (.md)",
  html: "HTML (.html)",
  json: "JSON (.json)",
  sarif: "SARIF (.sarif.json)",
};

const FORMAT_EXT: Record<ReportFormat, string> = {
  markdown: "md",
  html: "html",
  json: "json",
  sarif: "sarif.json",
};

const FORMAT_MIME: Record<ReportFormat, string> = {
  markdown: "text/markdown",
  html: "text/html",
  json: "application/json",
  sarif: "application/sarif+json",
};

export default function ImportReports({ backend }: Props) {
  const { state, refresh } = backend;
  const [file, setFile] = useState<File | null>(null);
  const [source, setSource] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<{ kind: "ok" | "bad"; text: string } | null>(null);
  const [importResult, setImportResult] = useState<ImportResult | null>(null);

  async function onImport(e: React.FormEvent) {
    e.preventDefault();
    if (!file) return;
    setFeedback(null);
    setBusy(true);
    setImportResult(null);
    try {
      const r = await importReport(file, source || null);
      setImportResult(r);
      setFeedback({
        kind: "ok",
        text: `通过 ${r.parser} 导入 ${r.imported} 条；去重后剩 ${r.unique} 条。`,
      });
      await refresh();
    } catch (err) {
      const text =
        err instanceof ApiError
          ? err.detail
          : err instanceof Error
            ? err.message
            : "导入失败";
      setFeedback({ kind: "bad", text });
    } finally {
      setBusy(false);
    }
  }

  async function downloadReport(format: ReportFormat) {
    setFeedback(null);
    try {
      const body = await getReportRaw(format);
      const blob = new Blob([body], { type: FORMAT_MIME[format] });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `guardscope-report.${FORMAT_EXT[format]}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setFeedback({ kind: "ok", text: `已下载 ${format.toUpperCase()} 报告。` });
    } catch (err) {
      const text =
        err instanceof ApiError
          ? err.detail
          : err instanceof Error
            ? err.message
            : "报告生成失败";
      setFeedback({ kind: "bad", text });
    }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1>导入与报告</h1>
          <div className="page-sub">
            接入本地扫描器输出，并导出格式化的报告。
          </div>
        </div>
      </div>

      {!state.online ? (
        <div className="alert is-info" style={{ marginBottom: 16 }}>
          <ShieldCheck size={16} aria-hidden="true" />
          <div>
            <strong>后端离线——导入与报告功能暂不可用。</strong>
            <p>请启动 GuardScope API 后再使用此功能。</p>
          </div>
        </div>
      ) : null}

      <div className="grid-2">
        <Panel title="导入一份扫描报告">
          <form className="form" onSubmit={onImport}>
            <div className="field">
              <label htmlFor="import-source">解析器</label>
              <select
                id="import-source"
                value={source}
                onChange={(e) => setSource(e.target.value)}
                disabled={!state.online}
              >
                <option value="">自动检测（根据文件名/内容）</option>
                {ALL_SOURCES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="import-file">报告文件</label>
              <input
                id="import-file"
                type="file"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                disabled={!state.online}
              />
              <span className="muted small">
                支持的格式：Nmap XML、OWASP ZAP JSON、SARIF 2.1.0、Bandit JSON、
                Semgrep JSON、Trivy JSON、pip-audit JSON。
              </span>
            </div>
            <div className="form-actions">
              <button
                type="submit"
                className="btn is-primary"
                disabled={!state.online || busy || !file}
              >
                <FileUp size={14} aria-hidden="true" />
                {busy ? "导入中…" : "导入报告"}
              </button>
            </div>
            {feedback ? (
              <div className={`alert is-${feedback.kind}`} role="status">
                {feedback.kind === "ok" ? (
                  <ShieldCheck size={14} aria-hidden="true" />
                ) : (
                  <TriangleAlert size={14} aria-hidden="true" />
                )}
                <p>{feedback.text}</p>
              </div>
            ) : null}
            {importResult ? (
              <div className="alert is-ok" role="status">
                <div>
                  <strong>{importResult.parser} 已解析 {importResult.imported} 条</strong>
                  <p className="small muted">
                    去重后剩 {importResult.unique} 条唯一漏洞。已加入仪表盘与漏洞发现视图。
                  </p>
                </div>
              </div>
            ) : null}
          </form>
        </Panel>

        <Panel title="报告导出">
          <p className="muted small" style={{ marginTop: 0 }}>
            基于当前漏洞集合生成报告并下载。所有格式均由服务端从归一化数据生成。
          </p>
          <div style={{ display: "grid", gap: 8 }}>
            {FORMATS.map((fmt) => (
              <button
                key={fmt}
                type="button"
                className="btn"
                onClick={() => downloadReport(fmt)}
                disabled={!state.online}
              >
                <Download size={14} aria-hidden="true" />
                {FORMAT_LABELS[fmt]}
              </button>
            ))}
          </div>
          {!state.online ? (
            <div style={{ marginTop: 12 }}>
              <State title="演示模式下不可生成报告" />
            </div>
          ) : null}
        </Panel>
      </div>
    </>
  );
}