import { ShieldAlert } from "lucide-react";

/**
 * Persistent red banner that sits at the top of the Offensive page.
 * Drives home that every action targets ONLY loopback labs that were
 * intentionally registered. No claim to novelty here.
 */
export default function ScopeWarning() {
  return (
    <div className="alert is-bad" role="alert" aria-live="polite">
      <ShieldAlert size={16} aria-hidden="true" />
      <div>
        <strong>仅限已授权的本地实验靶场</strong>
        <p>
          攻击工具只接受 <code>127.0.0.0/8</code> / <code>::1</code> 上的主机，且目标必须是通过
          <code>guardscope labs register</code> 注册到白名单中的实验靶场。
          任何公网 / 第三方 IP 都会在 HTTP 入口被 Scope Guard 直接拒绝（400）。
        </p>
      </div>
    </div>
  );
}
