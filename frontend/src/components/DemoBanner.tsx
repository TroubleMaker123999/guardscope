import { TriangleAlert } from "lucide-react";
import type { BackendState } from "../types";

/**
 * Always-visible honesty banner when the UI is running on demo data.
 *
 * We never silently present offline data as live. If the backend is up
 * and healthy, this component renders nothing.
 */
export default function DemoBanner({ state }: { state: BackendState }) {
  if (state.loading) {
    return (
      <div className="alert is-info" role="status" aria-live="polite">
        <TriangleAlert size={16} aria-hidden="true" />
        <div>
          <strong>正在连接 GuardScope API…</strong>
          <p>等待实时健康检查与漏洞数据返回。仅在 API 不可达时才显示演示数据。</p>
        </div>
      </div>
    );
  }
  if (state.online) return null;
  if (!state.demo) {
    return (
      <div className="alert is-bad" role="alert">
        <TriangleAlert size={16} aria-hidden="true" />
        <div>
          <strong>GuardScope API 出错</strong>
          <p>实时数据未能加载，也未切换到演示数据。当前显示的是上一次已知的数据。</p>
          {state.error ? <p className="small muted">原因：{state.error}</p> : null}
        </div>
      </div>
    );
  }
  return (
    <div className="alert is-warn" role="alert">
      <TriangleAlert size={16} aria-hidden="true" />
      <div>
        <strong>演示数据 / Demo data</strong>
        <p>
          GuardScope API（<code>{import.meta.env.VITE_API_BASE_URL ?? "/api"}</code>）当前不可达。
          为保证界面仍可演示，这里显示内置的演示漏洞与一个回环实验靶场。
          <strong>这里展示的数据并非来自你的数据库。</strong>
        </p>
        {state.error ? (
          <p className="small muted">原因：{state.error}</p>
        ) : null}
      </div>
    </div>
  );
}