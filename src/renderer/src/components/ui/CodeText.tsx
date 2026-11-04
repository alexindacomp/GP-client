import { useI18n } from '../../i18n/I18nContext';
import { useCopy } from '../../hooks/useCopy';
import { Button } from './Button';
import { CheckIcon, CopyIcon } from './Icon';
import styles from './CodeText.module.css';

const PIN_PREFIX = '--servercert=pin-sha256:';
/**
 * Tokens rendered as code inside prose: the servercert pin (placeholder `<…>` or a real 43+`=`
 * base64 pin) and the install commands main suggests. Trailing punctuation stays outside.
 */
const TOKEN_RE = /(--servercert=pin-sha256:(?:<…>|[A-Za-z0-9+/]{43}=)|sudo (?:port|apt) install openconnect)/;

function PinToken({ token }: { token: string }): React.JSX.Element {
  // The prefix never breaks; a long pin may wrap after it and inside itself (360px banners).
  return (
    <code className={styles.code}>
      <span className={styles.nowrap}>{PIN_PREFIX}</span>
      <wbr />
      <span className={styles.pin}>{token.slice(PIN_PREFIX.length)}</span>
    </code>
  );
}

function CommandToken({ command }: { command: string }): React.JSX.Element {
  const { t } = useI18n();
  const copy = useCopy();
  return (
    <span className={styles.command}>
      <code className={[styles.code, styles.nowrap].join(' ')}>{command}</code>
      <Button
        variant="subtle"
        iconOnly
        className={styles.copy}
        label={copy.copied ? t('common.copied') : t('onboarding.missing.copyCommand', { command })}
        icon={copy.copied ? <CheckIcon size={14} /> : <CopyIcon size={14} />}
        onClick={() => void copy.copy(command)}
      />
    </span>
  );
}

/** Plain text with known command/option tokens rendered as code (commands get a copy button). */
export function CodeText({ text }: { text: string }): React.JSX.Element {
  return (
    <>
      {text
        .split(TOKEN_RE)
        .map((part, i) =>
          i % 2 === 0 ? (
            part
          ) : part.startsWith(PIN_PREFIX) ? (
            <PinToken key={i} token={part} />
          ) : (
            <CommandToken key={i} command={part} />
          ),
        )}
    </>
  );
}
