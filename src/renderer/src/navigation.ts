import type { View } from './components/layout/NavBar';

export type { View };

/** Where to go, plus optional intent for the target screen. */
export interface NavTarget {
  view: View;
  /** Settings: focus a field (e.g. from the "set openconnect path" error action). */
  focus?: 'openconnectPath';
  /** Profiles: open the editor for this profile. */
  editProfileId?: string;
}

export type Navigate = (target: NavTarget) => void;
