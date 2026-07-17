import { useEffect, useMemo, useState } from "react";
import {
  Beaker,
  CheckCircle2,
  Crosshair,
  KeyRound,
  RefreshCw,
  Scan,
  Syringe,
} from "lucide-react";
import type {
  Availability,
  BackendState,
  HydraRequest,
  LabTarget,
  NmapRequest,
  NucleiRequest,
  RunHistoryEntry,
  SqlmapRequest,
} from "../types";
import { OffensiveApiError, getAvailability, getOffensiveLabs, getOffensiveRuns, runHydra, runNmap, runNuclei, runSqlmap } from "../lib/offensive";
import { Panel, State, Tag } from "../components/ui";
import ScopeWarning from "../components/ScopeWarning";

interface Props {
  backend: { state: BackendState };
}

const NMAP_SCAN_TYPES = [
  { value: "-sV", label: "服务版本探测 (-sV)" },
  { value: "-sT", label: "TCP 连接扫描 (-sT)" },
];
const HYDRA_SERVICES = ["ssh", "http-get", "http-post", "ftp", "mysql", "postgres"];
const NUCLEI_CATEGORIES = ["technologies", "exposures", "misconfiguration"];

export default function Offensive({ backend }: Props) {
  const [availability, setAvailability] = useState<Availability | null>(null);
  const [labs, setLabs] = useState<LabTarget[]>([]);
  const [runs, setRuns] = useState<RunHistoryEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    setLoading(true);
    setError(null);
    try {
      const [a, l, r] = await Promise.all([
        getAvailability(),
        getOffensiveLabs(),
        getOffensiveRuns(50),
      ]);
      setAvailability(a);
      setLabs(l);
      setRuns(r);
    } catch (err) {
      setError(err instanceof Error ? err.message : "无法连接到后端 offensive 接口");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (backend.state.online) refresh();
  }, [backend.state.online]);

  const anyToolReady = useMemo(
    () =>
      availability !== null &&
      (availability.nmap || availability.hydra || availability.sqlmap || availability.nuclei),
    [availability]
  );
  // `anyToolReady` is a forward-looking gate for a future "no tools available"
  // banner; keeping it as a memoized value to avoid recomputing on render.
  void anyToolReady;

  return (
    <>
      <div className="page-header">
        <div>
          <h1>漏洞测试</h1>
          <div className="page-sub">
            针对已注册的本地实验靶场调用 Nmap / Hydra / sqlmap / Nuclei。
            所有动作在调用前都会经过 Scope Guard 三重校验（loopback / 已注册 / 速率限制）。
          </div>
        </div>
        <button
          type="button"
          className="btn is-sm is-ghost"
          onClick={refresh}
          disabled={loading || !backend.state.online}
        >
          <RefreshCw size={14} aria-hidden="true" /> 刷新
        </button>
      </div>

      <ScopeWarning />

      {!backend.state.online ? (
        <div className="alert is-info" style={{ marginTop: 12 }}>
          <strong>后端离线。</strong> 该页面依赖 FastAPI 上的 <code>/offensive/*</code> 路由。
        </div>
      ) : null}

      {error ? (
        <div className="alert is-bad" role="alert" style={{ marginTop: 12 }}>
          <strong>加载失败：</strong> {error}
        </div>
      ) : null}

      {availability ? (
        <div className="kpi-grid" style={{ marginTop: 12 }}>
          <ToolTile label="Nmap" ready={availability.nmap} desc="端口与服务扫描" />
          <ToolTile label="Hydra" ready={availability.hydra} desc="在线凭证测试" />
          <ToolTile label="sqlmap" ready={availability.sqlmap} desc="SQL 注入检测" />
          <ToolTile label="Nuclei" ready={availability.nuclei} desc="N-day 模板" />
        </div>
      ) : null}

      <Panel title="可用实验靶场" actions={<span className="muted small">只列内置模板（Juice Shop / DVWA / Vuln Node）。到 <code>本地实验靶场</code> 页面手动注册。</span>}>
        {labs.length === 0 ? (
          <State title="暂无可用靶场" detail="后端 offline 或模板未配置。" />
        ) : (
          <div className="list-head" role="row">
            <div>键</div>
            <div>名称</div>
            <div>绑定</div>
            <div>用途</div>
          </div>
        )}
        {labs.map((t) => (
          <div key={t.key} className="list-row" style={{ cursor: "default" }}>
            <div className="cell-title"><code className="mono">{t.key}</code></div>
            <div className="cell-source">{t.name}</div>
            <div className="cell-asset">
              <Tag>{t.host}:{t.port}</Tag>
            </div>
            <div className="muted small">{t.description}</div>
          </div>
        ))}
      </Panel>

      <NmapPanel disabled={!availability?.nmap || !backend.state.online} onRan={refresh} />
      <HydraPanel disabled={!availability?.hydra || !backend.state.online} onRan={refresh} />
      <SqlmapPanel disabled={!availability?.sqlmap || !backend.state.online} onRan={refresh} />
      <NucleiPanel disabled={!availability?.nuclei || !backend.state.online} onRan={refresh} />

      <Panel title="最近攻击调用记录" actions={<span className="muted small">来自 <code>offensive/audit.db</code></span>}>
        {runs.length === 0 ? (
          <State title="暂无调用记录" detail="发起一次扫描或爆破后这里会出现历史。" />
        ) : (
          <div>
            {runs.map((r) => (
              <div key={r.id} className="list-row" style={{ cursor: "default" }}>
                <div className="cell-title">
                  <Tag>{r.action}</Tag>
                </div>
                <div className="cell-source">{new Date(r.timestamp * 1000).toLocaleString()}</div>
                <div className="cell-asset">{r.target}</div>
                <div className="muted small">
                  退出={r.exit_code ?? "?"} · {r.summary}
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </>
  );
}

function ToolTile({ label, ready, desc }: { label: string; ready: boolean; desc: string }) {
  return (
    <div className={`kpi${ready ? " is-ok" : " is-bad"}`}>
      <div className="kpi-label">
        {ready ? <CheckCircle2 size={14} aria-hidden="true" /> : <Crosshair size={14} aria-hidden="true" />}
        {label}
      </div>
      <div className="kpi-value tabular">{ready ? "已安装" : "缺失"}</div>
      <div className="kpi-sub">{desc}</div>
    </div>
  );
}


// ---------------------------------------------------------------------------
// 5 个 runner 面板 — 每个独立表单 + 结果区域
// ---------------------------------------------------------------------------

function PanelRunnerFrame(props: {
  title: string;
  icon: JSX.Element;
  disabled: boolean;
  onRan: () => void;
  run: (setBusy: (b: boolean) => void, setResult: (r: ResultLine[]) => void, setError: (e: string | null) => void) => Promise<void>;
  children: React.ReactNode;
}) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ResultLine[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  return (
    <Panel
      title={
        <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
          {props.icon} {props.title}
        </span>
      }
    >
      <form
        className="form"
        onSubmit={async (e) => {
          e.preventDefault();
          setErr(null);
          setResult(null);
          await props.run(setBusy, setResult, setErr);
          props.onRan();
        }}
      >
        <fieldset disabled={props.disabled || busy} style={{ border: 0, padding: 0, margin: 0 }}>
          {props.children}
          <div className="form-actions">
            <button type="submit" className="btn is-primary" disabled={props.disabled || busy}>
              {busy ? "执行中…" : "运行"}
            </button>
          </div>
        </fieldset>
      </form>

      {err ? (
        <div className="alert is-bad" role="alert" style={{ marginTop: 12 }}>
          <strong>执行失败：</strong> {err}
        </div>
      ) : null}

      {result && result.length > 0 ? (
        <div className="panel" style={{ marginTop: 16 }}>
          <header className="panel-header">
            <h2>结果</h2>
          </header>
          <div className="panel-body">
            <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 6 }}>
              {result.map((r, i) => (
                <li key={i} className="list-row" style={{ cursor: "default" }}>
                  <Tag>{r.label}</Tag>
                  <div className="cell-title mono">{r.value}</div>
                </li>
              ))}
            </ul>
          </div>
        </div>
      ) : null}
    </Panel>
  );
}

type ResultLine = { label: string; value: string };

function NmapPanel({ disabled, onRan }: { disabled: boolean; onRan: () => void }) {
  const [target, setTarget] = useState("127.0.0.1");
  const [ports, setPorts] = useState("1-1024");
  const [scanType, setScanType] = useState("-sV");

  return (
    <PanelRunnerFrame
      title="Nmap 端口扫描"
      icon={<Scan size={14} aria-hidden="true" />}
      disabled={disabled}
      onRan={onRan}
      run={async (setBusy, setResult, setError) => {
        setBusy(true);
        try {
          const body: NmapRequest = { target, ports, scan_type: scanType };
          const r = await runNmap(body);
          setResult([
            { label: "工具", value: r.tool },
            { label: "目标", value: r.target },
            { label: "摘要", value: r.summary },
            { label: "输出", value: r.output_path ?? "—" },
          ]);
        } catch (err) {
          setError(err instanceof Error ? err.message : "nmap 调用失败");
        } finally {
          setBusy(false);
        }
      }}
    >
      <div className="field">
        <label htmlFor="nmap-target">目标主机（仅 loopback）</label>
        <input id="nmap-target" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="127.0.0.1" required />
      </div>
      <div className="field">
        <label htmlFor="nmap-ports">端口</label>
        <input id="nmap-ports" value={ports} onChange={(e) => setPorts(e.target.value)} placeholder="1-1024" />
      </div>
      <div className="field">
        <label htmlFor="nmap-type">扫描类型</label>
        <select id="nmap-type" value={scanType} onChange={(e) => setScanType(e.target.value)}>
          {NMAP_SCAN_TYPES.map((t) => (
            <option key={t.value} value={t.value}>
              {t.label}
            </option>
          ))}
        </select>
      </div>
    </PanelRunnerFrame>
  );
}

function HydraPanel({ disabled, onRan }: { disabled: boolean; onRan: () => void }) {
  const [target, setTarget] = useState("127.0.0.1");
  const [service, setService] = useState("ssh");
  const [username, setUsername] = useState("root");
  const [wordlist, setWordlist] = useState("/usr/share/dict/words");
  const [port, setPort] = useState("");

  return (
    <PanelRunnerFrame
      title="Hydra 在线爆破"
      icon={<KeyRound size={14} aria-hidden="true" />}
      disabled={disabled}
      onRan={onRan}
      run={async (setBusy, setResult, setError) => {
        setBusy(true);
        try {
          const body: HydraRequest = {
            target,
            service,
            username,
            wordlist_path: wordlist,
            port: port ? Number(port) : undefined,
          };
          const r = await runHydra(body);
          setResult([
            { label: "工具", value: r.tool },
            { label: "目标", value: r.target },
            { label: "摘要", value: r.summary },
            { label: "输出", value: r.output_path ?? "—" },
          ]);
        } catch (err) {
          setError(err instanceof Error ? err.message : "hydra 调用失败");
        } finally {
          setBusy(false);
        }
      }}
    >
      <div className="field">
        <label htmlFor="hydra-target">目标主机</label>
        <input id="hydra-target" value={target} onChange={(e) => setTarget(e.target.value)} required />
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <div className="field">
          <label htmlFor="hydra-service">服务</label>
          <select id="hydra-service" value={service} onChange={(e) => setService(e.target.value)}>
            {HYDRA_SERVICES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="hydra-port">端口（可选）</label>
          <input id="hydra-port" type="number" value={port} onChange={(e) => setPort(e.target.value)} placeholder="22" />
        </div>
      </div>
      <div className="field">
        <label htmlFor="hydra-user">用户名</label>
        <input id="hydra-user" value={username} onChange={(e) => setUsername(e.target.value)} required />
      </div>
      <div className="field">
        <label htmlFor="hydra-wordlist">本地字典路径</label>
        <input id="hydra-wordlist" value={wordlist} onChange={(e) => setWordlist(e.target.value)} required />
        <span className="muted small">后端会校验文件存在性；不支持 <code>rockyou.txt</code> 默认词表（须显式开启 <code>HYDRA_ALLOW_ROCKYOU=1</code>）。</span>
      </div>
    </PanelRunnerFrame>
  );
}

function SqlmapPanel({ disabled, onRan }: { disabled: boolean; onRan: () => void }) {
  const [target, setTarget] = useState("127.0.0.1");
  const [url, setUrl] = useState("http://127.0.0.1:3000/rest/products/search?q=");
  const [level, setLevel] = useState(1);
  const [risk, setRisk] = useState(1);

  return (
    <PanelRunnerFrame
      title="sqlmap SQL 注入"
      icon={<Syringe size={14} aria-hidden="true" />}
      disabled={disabled}
      onRan={onRan}
      run={async (setBusy, setResult, setError) => {
        setBusy(true);
        try {
          const body: SqlmapRequest = { target, url, level, risk };
          const r = await runSqlmap(body);
          setResult([
            { label: "工具", value: r.tool },
            { label: "目标", value: r.target },
            { label: "可注入", value: r.injectable ? "是" : "否" },
            { label: "摘要", value: r.summary },
            { label: "输出", value: r.output_path ?? "—" },
          ]);
        } catch (err) {
          setError(err instanceof Error ? err.message : "sqlmap 调用失败");
        } finally {
          setBusy(false);
        }
      }}
    >
      <div className="field">
        <label htmlFor="sqli-target">目标主机</label>
        <input id="sqli-target" value={target} onChange={(e) => setTarget(e.target.value)} required />
      </div>
      <div className="field">
        <label htmlFor="sqli-url">URL（含待测参数）</label>
        <input id="sqli-url" value={url} onChange={(e) => setUrl(e.target.value)} required />
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <div className="field">
          <label htmlFor="sqli-level">Level（1–2）</label>
          <input id="sqli-level" type="number" min={1} max={2} value={level} onChange={(e) => setLevel(Number(e.target.value))} />
        </div>
        <div className="field">
          <label htmlFor="sqli-risk">Risk（1–2）</label>
          <input id="sqli-risk" type="number" min={1} max={2} value={risk} onChange={(e) => setRisk(Number(e.target.value))} />
        </div>
      </div>
      <span className="muted small">
        sqlmap 的危险 flag（<code>--os-shell</code>、<code>--file-write</code> 等）会被后端 Scope Guard 拒绝。
      </span>
    </PanelRunnerFrame>
  );
}

function NucleiPanel({ disabled, onRan }: { disabled: boolean; onRan: () => void }) {
  const [target, setTarget] = useState("127.0.0.1");
  const [url, setUrl] = useState("http://127.0.0.1:3000/");
  const [categories, setCategories] = useState<string[]>(["technologies", "exposures"]);

  return (
    <PanelRunnerFrame
      title="Nuclei 模板扫描"
      icon={<Beaker size={14} aria-hidden="true" />}
      disabled={disabled}
      onRan={onRan}
      run={async (setBusy, setResult, setError) => {
        setBusy(true);
        try {
          const body: NucleiRequest = { target, url, categories };
          const r = await runNuclei(body);
          setResult([
            { label: "工具", value: r.tool },
            { label: "目标", value: r.target },
            { label: "命中数", value: String(r.matched ?? 0) },
            { label: "摘要", value: r.summary },
            { label: "输出", value: r.output_path ?? "—" },
          ]);
        } catch (err) {
          // The Nuclei binary may not be installed — surface that distinctly.
          if (err instanceof OffensiveApiError && err.status === 412) {
            setError("nuclei 未安装；可在目标机器上 go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest");
          } else {
            setError(err instanceof Error ? err.message : "nuclei 调用失败");
          }
        } finally {
          setBusy(false);
        }
      }}
    >
      <div className="field">
        <label htmlFor="nuclei-target">目标主机</label>
        <input id="nuclei-target" value={target} onChange={(e) => setTarget(e.target.value)} required />
      </div>
      <div className="field">
        <label htmlFor="nuclei-url">URL</label>
        <input id="nuclei-url" value={url} onChange={(e) => setUrl(e.target.value)} required />
      </div>
      <div className="field">
        <label>模板类别</label>
        <div className="row" style={{ flexWrap: "wrap", gap: 8 }}>
          {NUCLEI_CATEGORIES.map((c) => (
            <label key={c} style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
              <input
                type="checkbox"
                checked={categories.includes(c)}
                onChange={(e) =>
                  setCategories(
                    e.target.checked
                      ? [...categories, c]
                      : categories.filter((x) => x !== c)
                  )
                }
              />
              <code className="mono">{c}</code>
            </label>
          ))}
        </div>
        <span className="muted small">本机只允许 info / low / medium 严重级——high/critical 模板里常含利用链。</span>
      </div>
    </PanelRunnerFrame>
  );
}
