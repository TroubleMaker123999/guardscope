import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, getDemoFindings, getDemoLabs, getHealth, listLabs, listFindings } from "./api";
import type { BackendState, Finding, Health, Lab } from "../types";

/**
 * Single source of truth for "is the backend reachable?".
 *
 * Components subscribe via `useBackend()` which exposes both the live state
 * and a `refresh()` helper. When the backend is offline we surface demo data
 * and a banner so the UI is never silently lying about being live.
 */
export function useBackend(): {
  state: BackendState;
  findings: Finding[];
  labs: Lab[];
  refresh: () => Promise<void>;
} {
  const [state, setState] = useState<BackendState>({
    online: false,
    demo: false,
    loading: true,
  });
  const [findings, setFindings] = useState<Finding[]>([]);
  const [labs, setLabs] = useState<Lab[]>([]);
  const aliveRef = useRef(true);

  const refresh = useCallback(async () => {
    try {
      const health: Health = await getHealth();
      if (!aliveRef.current) return;
      const [realFindings, realLabs] = await Promise.all([
        listFindings({ sort: "risk", limit: 1000 }),
        listLabs(),
      ]);
      if (!aliveRef.current) return;
      setFindings(realFindings);
      setLabs(realLabs);
      setState({
        online: true,
        demo: false,
        loading: false,
        version: health.version,
        db: health.db,
      });
    } catch (err) {
      if (!aliveRef.current) return;
      const isNetworkFailure = err instanceof ApiError && err.status === 0;
      setState({
        online: false,
        demo: isNetworkFailure,
        loading: false,
        error: err instanceof Error ? err.message : "unknown error",
      });
      if (isNetworkFailure) {
        setFindings(getDemoFindings());
        setLabs(getDemoLabs());
      }
    }
  }, []);

  useEffect(() => {
    aliveRef.current = true;
    refresh();
    return () => {
      aliveRef.current = false;
    };
  }, [refresh]);

  return { state, findings, labs, refresh };
}