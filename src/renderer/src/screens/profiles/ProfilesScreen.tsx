import { useState } from 'react';
import type { Profile, VpnState } from '@shared/ipc';
import { useI18n } from '../../i18n/I18nContext';
import { useAppData } from '../../state/AppData';
import { isIdle } from '../../hooks/useVpnState';
import { Page } from '../../components/layout/Page';
import { Button } from '../../components/ui/Button';
import { BackIcon, PlusIcon } from '../../components/ui/Icon';
import { ProfileForm } from './ProfileForm';
import { ProfileList } from './ProfileList';
import { DeleteProfileDialog } from './DeleteProfileDialog';

type Mode = { kind: 'list' } | { kind: 'new' } | { kind: 'edit'; id: string };

interface Props {
  state: VpnState | null;
  /** Open the editor for this profile right away (from an error action). */
  initialEditId?: string;
}

export function ProfilesScreen({ state, initialEditId }: Props): React.JSX.Element {
  const { t } = useI18n();
  const { profiles } = useAppData();
  const [mode, setMode] = useState<Mode>(initialEditId ? { kind: 'edit', id: initialEditId } : { kind: 'list' });
  const [toDelete, setToDelete] = useState<Profile | null>(null);

  const activeId = state && !isIdle(state.status) ? state.profileId : undefined;
  const editing = mode.kind === 'edit' ? profiles.find((p) => p.id === mode.id) : undefined;
  const toList = (): void => setMode({ kind: 'list' });

  if (mode.kind === 'new' || editing) {
    return (
      <Page
        title={editing ? t('profiles.editTitle') : t('profiles.newTitle')}
        actions={<Button variant="subtle" iconOnly label={t('profiles.back')} icon={<BackIcon />} onClick={toList} />}
      >
        <ProfileForm key={editing?.id ?? 'new'} profile={editing} onSaved={toList} onCancel={toList} />
      </Page>
    );
  }

  return (
    <Page
      title={t('profiles.title')}
      actions={
        <Button variant="subtle" icon={<PlusIcon size={16} />} onClick={() => setMode({ kind: 'new' })}>
          {t('profiles.add')}
        </Button>
      }
    >
      <ProfileList
        profiles={profiles}
        activeId={activeId}
        onEdit={(p) => setMode({ kind: 'edit', id: p.id })}
        onDelete={setToDelete}
        onAdd={() => setMode({ kind: 'new' })}
      />
      {toDelete ? <DeleteProfileDialog profile={toDelete} onClose={() => setToDelete(null)} /> : null}
    </Page>
  );
}
