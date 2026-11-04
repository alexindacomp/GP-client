import type { Profile } from '@shared/ipc';
import { useI18n } from '../../i18n/I18nContext';
import { portalHost } from '../../lib/format';
import { Button } from '../../components/ui/Button';
import { DeleteIcon, EditIcon, PlusIcon } from '../../components/ui/Icon';
import styles from './ProfileList.module.css';

interface Props {
  profiles: Profile[];
  /** Profile with a running connection: cannot be deleted. */
  activeId: string | undefined;
  onEdit: (p: Profile) => void;
  onDelete: (p: Profile) => void;
  onAdd: () => void;
}

export function ProfileList({ profiles, activeId, onEdit, onDelete, onAdd }: Props): React.JSX.Element {
  const { t } = useI18n();
  if (profiles.length === 0) {
    return (
      <div className={styles.empty}>
        <p>{t('profiles.empty')}</p>
        <Button variant="primary" icon={<PlusIcon size={16} />} onClick={onAdd}>
          {t('profiles.addLong')}
        </Button>
      </div>
    );
  }
  return (
    <ul className={styles.list}>
      {profiles.map((p) => {
        const inUse = p.id === activeId;
        return (
          <li key={p.id} className={styles.item}>
            <div className={styles.text}>
              <span className={styles.name}>{p.name}</span>
              <span className={styles.meta}>
                {portalHost(p.portalUrl)} · {t(`profiles.authMode.${p.authMode}` as const)}
              </span>
              {inUse ? <span className={styles.badge}>{t('profiles.inUse')}</span> : null}
            </div>
            <Button
              variant="subtle"
              iconOnly
              label={t('profiles.editLabel', { name: p.name })}
              icon={<EditIcon size={16} />}
              onClick={() => onEdit(p)}
            />
            <Button
              variant="subtle"
              iconOnly
              label={t('profiles.deleteLabel', { name: p.name })}
              icon={<DeleteIcon size={16} />}
              onClick={() => onDelete(p)}
              disabled={inUse}
            />
          </li>
        );
      })}
    </ul>
  );
}
