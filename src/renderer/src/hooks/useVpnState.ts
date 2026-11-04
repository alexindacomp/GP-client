import { useEffect, useState } from 'react';
import type { VpnState, VpnStatus } from '@shared/ipc';

/** Statuses from which `vpn.connect()` is allowed. */
export function isIdle(status: VpnStatus): boolean {
  return status === 'disconnected' || status === 'error';
}

/** A connection attempt is running (the toggle acts as "cancel"). */
export function isBusy(status: VpnStatus): boolean {
  return status === 'prelogin' || status === 'authenticating' || status === 'connecting' || status === 'reconnecting';
}

/**
 * Live VPN state. Subscribes before reading the snapshot so no transition is missed;
 * a snapshot that arrives after the first event is ignored as stale.
 */
export function useVpnState(): VpnState | null {
  const [state, setState] = useState<VpnState | null>(null);

  useEffect(() => {
    let live = true;
    let gotEvent = false;
    const unsubscribe = window.gp.vpn.onState((s) => {
      gotEvent = true;
      if (live) setState(s);
    });
    window.gp.vpn.getState().then(
      (s) => {
        if (live && !gotEvent) setState(s);
      },
      (err: unknown) => {
        console.error('Failed to read VPN state', err);
        if (live && !gotEvent) setState({ status: 'disconnected' });
      },
    );
    return () => {
      live = false;
      unsubscribe();
    };
  }, []);

  return state;
}
