import type { Profile } from '@shared/ipc';
import { useI18n } from '../../i18n/I18nContext';
import { useAppData } from '../../state/AppData';
import { useAsyncAction } from '../../hooks/useAsyncAction';
import { localizeIpcError } from '../../lib/ipcErrors';
import { Dialog, DialogActions } from '../../components/ui/Dialog';
import { Button } from '../../components/ui/Button';
import { Banner } from '../../components/ui/Banner';

export function DeleteProfileDialog({
  profile,
  onClose,
}: {
  profile: Profile;
  onClose: () => void;
}): React.JSX.Element {
  const { t } = useI18n();
  const { removeProfile } = useAppData();
  const remove = useAsyncAction();

  const confirm = (): void => {
    void remove
      .run(() => removeProfile(profile.id))
      .then((ok) => {
        if (ok) onClose();
      });
  };

  return (
    <Dialog
      role="alertdialog"
      title={t('profiles.deleteTitle')}
      description={t('profiles.deleteText', { name: profile.name })}
      onCancel={() => !remove.pending && onClose()}
    >
      {remove.error ? <Banner tone="error" role="alert" title={localizeIpcError(t, remove.error).text} /> : null}
      <DialogActions>
        <Button onClick={onClose} disabled={remove.pending} data-autofocus>
          {t('common.cancel')}
        </Button>
        <Button variant="danger" onClick={confirm} disabled={remove.pending}>
          {t('common.delete')}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
