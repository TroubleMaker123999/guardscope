import { useEffect, useState } from "react";
import {
  Activity,
  ClipboardList,
  Crosshair,
  FlaskConical,
  LayoutDashboard,
  Upload,
} from "lucide-react";
import Dashboard from "./pages/Dashboard";
import Findings from "./pages/Findings";
import Labs from "./pages/Labs";
import ImportReports from "./pages/ImportReports";
import Offensive from "./pages/Offensive";
import DemoBanner from "./components/DemoBanner";
import { useBackend } from "./lib/useBackend";
import type { BackendState } from "./types";

export type RouteId = "dashboard" | "findings" | "labs" | "import" | "offensive";

const ROUTES: Array<{ id: RouteId; label: string; path: string; icon: typeof Activity }> = [
  { id: "dashboard", label: "仪表盘", path: "#/dashboard", icon: LayoutDashboard },
  { id: "findings", label: "漏洞发现", path: "#/findings", icon: ClipboardList },
  { id: "labs", label: "本地实验靶场", path: "#/labs", icon: FlaskConical },
  { id: "import", label: "导入与报告", path: "#/import", icon: Upload },
  { id: "offensive", label: "漏洞测试", path: "#/offensive", icon: Crosshair },
];

function readRoute(): RouteId {
  const h = window.location.hash;
  if (h.startsWith("#/findings")) return "findings";
  if (h.startsWith("#/labs")) return "labs";
  if (h.startsWith("#/import")) return "import";
  if (h.startsWith("#/offensive")) return "offensive";
  return "dashboard";
}

const TITLES: Record<RouteId, { title: string; sub: string }> = {
  dashboard: {
    title: "安全运营控制台",
    sub: "面向防御的本地实验靶场漏洞管理",
  },
  findings: {
    title: "漏洞发现",
    sub: "已归一化、去重、并按风险评分",
  },
  labs: {
    title: "本地实验靶场",
    sub: "仅回环地址上的验证目标",
  },
  import: {
    title: "导入与报告",
    sub: "接入扫描器输出并导出报告",
  },
  offensive: {
    title: "漏洞测试",
    sub: "对已注册靶场调用 Nmap / Hydra / sqlmap / Nuclei",
  },
};

export default function App() {
  const [route, setRoute] = useState<RouteId>(readRoute);
  const backend = useBackend();

  useEffect(() => {
    const onHash = () => setRoute(readRoute());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const title = TITLES[route];

  let body: JSX.Element;
  if (route === "dashboard") {
    body = <Dashboard backend={backend} onNavigate={setRoute} />;
  } else if (route === "findings") {
    body = <Findings backend={backend} />;
  } else if (route === "labs") {
    body = <Labs backend={backend} />;
  } else if (route === "offensive") {
    body = <Offensive backend={backend} />;
  } else {
    body = <ImportReports backend={backend} />;
  }

  return (
    <div className="app">
      <aside className="sidebar" aria-label="主导航">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            GS
          </div>
          <div>
            <div className="brand-name">GuardScope</div>
            <div className="brand-tag">v{backend.state.version ?? "0.1.0"}</div>
          </div>
        </div>

        <div className="nav-section">工作区</div>
        {ROUTES.map((r) => {
          const Icon = r.icon;
          const isActive = route === r.id;
          return (
            <a
              key={r.id}
              href={r.path}
              className={`nav-link${isActive ? " is-active" : ""}`}
              aria-current={isActive ? "page" : undefined}
            >
              <Icon size={16} className="nav-icon" aria-hidden="true" />
              <span>{r.label}</span>
              {r.id === "findings" && backend.findings.length > 0 ? (
                <span className="nav-badge">{backend.findings.length}</span>
              ) : null}
              {r.id === "labs" && backend.labs.length > 0 ? (
                <span className="nav-badge">{backend.labs.length}</span>
              ) : null}
            </a>
          );
        })}

        <div className="sidebar-footer">
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
            <span className="scope-badge">仅本地实验靶场</span>
          </div>
          <div>
            面向防御的、授权范围内的漏洞管理。GuardScope 拒绝任何不在回环接口上的验证目标。
          </div>
        </div>
      </aside>

      <header className="topbar" role="banner">
        <div className="topbar-title">
          <h1>{title.title}</h1>
          <span className="topbar-sub">{title.sub}</span>
        </div>
        <div className="topbar-right">
          <HealthPill state={backend.state} />
          <button
            type="button"
            className="btn is-ghost is-sm"
            onClick={() => backend.refresh()}
            aria-label="从后端刷新数据"
          >
            <Activity size={14} aria-hidden="true" /> 刷新
          </button>
        </div>
      </header>

      <main className="main" id="main">
        <DemoBanner state={backend.state} />
        {body}
      </main>
    </div>
  );
}

function HealthPill({ state }: { state: BackendState }) {
  if (state.loading) {
    return (
      <span className="health-pill is-demo" role="status">
        <span className="dot" aria-hidden="true" />
        正在连接
      </span>
    );
  }
  if (state.online) {
    return (
      <span className="health-pill is-ok" role="status">
        <span className="dot" aria-hidden="true" />
        后端在线
      </span>
    );
  }
  if (state.demo) {
    return (
      <span className="health-pill is-demo" role="status">
        <span className="dot" aria-hidden="true" />
        演示数据
      </span>
    );
  }
  return (
    <span className="health-pill is-bad" role="status">
      <span className="dot" aria-hidden="true" />
      后端离线
    </span>
  );
}