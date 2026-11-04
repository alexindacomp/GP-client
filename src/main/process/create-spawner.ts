import { chooseElevation } from './elevation';
import { LocalSpawner } from './local-spawner';
import { DarwinOsascriptSpawner } from './darwin-osascript-spawner';
import { Win32ElevatedSpawner } from './win32-elevated-spawner';
import type { ProcessSpawner, SpawnRequest, VpnProcess } from './types';

function isRoot(): boolean {
  return typeof process.getuid === 'function' && process.getuid() === 0;
}

export type ElevationLog = (msg: string) => void;

/** Picks the elevation strategy for the current OS at spawn time. */
export function createPlatformSpawner(platform: NodeJS.Platform, log: ElevationLog): ProcessSpawner {
  return {
    async spawn(req: SpawnRequest): Promise<VpnProcess> {
      const method = chooseElevation({ platform, isRoot: isRoot() });
      log(`Starting openconnect (elevation: ${method})`);
      switch (method) {
        case 'uac':
          return new Win32ElevatedSpawner().spawn(req);
        case 'osascript':
          return new DarwinOsascriptSpawner().spawn(req);
        default:
          return new LocalSpawner(method).spawn(req);
      }
    },
  };
}
