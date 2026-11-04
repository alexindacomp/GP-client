import { useI18n } from '../../i18n/I18nContext';
import { Page } from '../../components/layout/Page';
import { Card } from '../../components/layout/Card';
import { ProfileForm } from '../profiles/ProfileForm';
import styles from './Onboarding.module.css';

/** First run: no profiles yet. Saving the form switches the connect screen to its normal state. */
export function NoProfiles(): React.JSX.Element {
  const { t } = useI18n();
  return (
    <Page title={t('onboarding.noProfiles.title')}>
      <p className={styles.lead}>{t('onboarding.noProfiles.text')}</p>
      <Card>
        <ProfileForm onSaved={() => undefined} />
      </Card>
    </Page>
  );
}
