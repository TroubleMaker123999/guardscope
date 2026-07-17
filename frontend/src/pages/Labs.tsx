import { useState } from "react";
import { FlaskConical, Plus, ShieldCheck, TriangleAlert } from "lucide-react";
import { ApiError, checkScope, registerLab } from "../lib/api";
import type { BackendState, Lab } from "../types";
import { Panel, State } from "../components/ui";

interface Props {
  backend: {
    state: BackendState;
    labs: Lab[];
    refresh: () => Promise<void>;
  };
}

interface FormState {
  name: string;
  host: string;
  port: string;
  description: string;
}

const EMPTY_FORM: FormState = { name: "", host: "127.0.0.1", port: "8080", description: "" };

export default function Labs({ backend }: Props) {
  const { labs, state, refresh } = backend;
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [submitting, setSubmitting] = useState(false);
  const [feedback, setFeedback] = useState<{ kind: "ok" | "bad"; text: string } | null>(null);

  // Scope check form
  const [scopeHost, setScopeHost] = useState("127.0.0.1");
  const [scopePort, setScopePort] = useState("");
  const [scopeResult, setScopeResult] = useState<
    | { kind: "ok"; text: string }
    | { kind: "bad"; text: string }
    | null
  >(null);
  const [scopeLoading, setScopeLoading] = useState(false);

  async function onRegister(e: React.FormEvent) {
    e.preventDefault();
    setFeedback(null);
    setSubmitting(true);
    try {
      await registerLab({
        name: form.name.trim(),
        host: form.host.trim(),
        port: Number(form.port),
        description: form.description.trim(),
      });
      setForm({ name: "", host: form.host, port: form.port, description: "" });
      setFeedback({ kind: "ok", text: `已注册靶场 "${form.name}"。` });
      await refresh();
    } catch (err) {
      const text =
        err instanceof ApiError
          ? err.detail
          : err instanceof Error
            ? err.message
            : "注册失败";
      setFeedback({ kind: "bad", text });
    } finally {
      setSubmitting(false);
    }
  }

  async function onScopeCheck(e: React.FormEvent) {
    e.preventDefault();
    setScopeResult(null);
    setScopeLoading(true);
    try {
      const r = await checkScope(scopeHost.trim(), scopePort ? Number(scopePort) : undefined);
      if (r.in_scope) {
        setScopeResult({ kind: "ok", text: `在范围内：${r.host}` });
      } else {
        setScopeResult({ kind: "bad", text: r.reason || "超出范围" });
      }
    } catch (err) {
      const text =
        err instanceof ApiError
          ? err.detail
          : err instanceof Error
            ? err.message
            : "范围检查失败";
      setScopeResult({ kind: "bad", text });
    } finally {
      setScopeLoading(false);
    }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1>本地实验靶场</h1>
          <div className="page-sub">
            仅回环地址（<code>localhost</code>、<code>127.0.0.1</code>、{" "}
            <code>::1</code>）允许被注册。
          </div>
        </div>
        <span className="scope-badge">
          <FlaskConical size={12} aria-hidden="true" /> 仅回环地址
        </span>
      </div>

      {!state.online ? (
        <div className="alert is-info" style={{ marginBottom: 16 }}>
          <ShieldCheck size={16} aria-hidden="true" />
          <div>
            <strong>后端离线——靶场注册功能暂不可用。</strong>
            <p>
              请先启动 GuardScope API（<code>guardscope serve</code>）以注册真实靶场。下方范围检查演示仍然可以基于演示数据工作。
            </p>
          </div>
        </div>
      ) : null}

      <div className="grid-2">
        <Panel title="已注册靶场">
          {labs.length === 0 ? (
            <State
              title="暂无已注册的靶场"
              detail={
                state.online
                  ? "使用右侧表单注册你的第一个回环实验靶场。"
                  : "后端离线时，演示靶场会显示在此。"
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

        <Panel title="注册一个新靶场">
          <form className="form" onSubmit={onRegister}>
            <div className="field">
              <label htmlFor="lab-name">名称</label>
              <input
                id="lab-name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="demo-nginx"
                required
                disabled={!state.online}
              />
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 12 }}>
              <div className="field">
                <label htmlFor="lab-host">主机</label>
                <input
                  id="lab-host"
                  value={form.host}
                  onChange={(e) => setForm({ ...form, host: e.target.value })}
                  placeholder="127.0.0.1"
                  required
                  disabled={!state.online}
                />
              </div>
              <div className="field">
                <label htmlFor="lab-port">端口</label>
                <input
                  id="lab-port"
                  type="number"
                  min={1}
                  max={65535}
                  value={form.port}
                  onChange={(e) => setForm({ ...form, port: e.target.value })}
                  required
                  disabled={!state.online}
                />
              </div>
            </div>
            <div className="field">
              <label htmlFor="lab-desc">描述</label>
              <input
                id="lab-desc"
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                placeholder="本地 nginx 演示靶场（docker compose up -d）"
                disabled={!state.online}
              />
            </div>
            <div className="form-actions">
              <button
                type="submit"
                className="btn is-primary"
                disabled={!state.online || submitting}
              >
                <Plus size={14} aria-hidden="true" />
                {submitting ? "注册中…" : "注册靶场"}
              </button>
              <span className="muted small">
                非回环主机在 API 入口被直接拒绝。
              </span>
            </div>
            {feedback ? (
              <div className={`alert is-${feedback.kind}`} role="status">
                {feedback.kind === "ok" ? <ShieldCheck size={14} /> : <TriangleAlert size={14} />}
                <p>{feedback.text}</p>
              </div>
            ) : null}
          </form>
        </Panel>
      </div>

      <div style={{ height: 16 }} />

      <Panel title="范围检查">
        <form className="form" onSubmit={onScopeCheck}>
          <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr auto", gap: 12, alignItems: "end" }}>
            <div className="field">
              <label htmlFor="scope-host">主机</label>
              <input
                id="scope-host"
                value={scopeHost}
                onChange={(e) => setScopeHost(e.target.value)}
                placeholder="example.com 或 127.0.0.1"
                required
              />
            </div>
            <div className="field">
              <label htmlFor="scope-port">端口（可选）</label>
              <input
                id="scope-port"
                type="number"
                min={1}
                max={65535}
                value={scopePort}
                onChange={(e) => setScopePort(e.target.value)}
                placeholder="8080"
              />
            </div>
            <button type="submit" className="btn" disabled={scopeLoading}>
              {scopeLoading ? "检查中…" : "开始检查"}
            </button>
          </div>
          {scopeResult ? (
            <div className={`scope-result is-${scopeResult.kind}`} role="status">
              {scopeResult.text}
            </div>
          ) : (
            <p className="muted small">
              范围守卫会拒绝任何不能解析为回环地址的主机。
            </p>
          )}
        </form>
      </Panel>
    </>
  );
}