/**
 * User flows across screens, driven through the UI against a mocked `window.gp`.
 */
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AuthPrompt, SystemInfo } from '@shared/ipc';
import { App } from './App';
import { installGpMock, PROFILE } from './test/gpMock';

const root = document.documentElement;
afterEach(() => {
  delete root.dataset.theme;
  delete root.dataset.platform;
});

describe('theme (acceptance #5)', () => {
  async function openSettings(): Promise<void> {
    await userEvent.click(await screen.findByRole('button', { name: 'Настройки' }));
  }
  const pick = (name: 'Системная' | 'Светлая' | 'Тёмная'): Promise<void> =>
    userEvent.click(screen.getByRole('radio', { name }));

  it('cycles system → light → dark → system, applying data-theme on every click without reload', async () => {
    const mock = installGpMock({ settings: { theme: 'system' }, info: { shouldUseDarkColors: false } });
    render(<App />);
    await waitFor(() => expect(root.dataset.theme).toBe('light')); // OS is light
    await openSettings();

    await pick('Светлая');
    expect(screen.getByRole('radio', { name: 'Светлая' })).toBeChecked();
    await waitFor(() => expect(root.dataset.theme).toBe('light'));
    await pick('Тёмная');
    await waitFor(() => expect(root.dataset.theme).toBe('dark'));
    // Back to "system" must leave dark and follow the (light) OS again.
    await pick('Системная');
    await waitFor(() => expect(root.dataset.theme).toBe('light'));
    expect(screen.getByRole('radio', { name: 'Системная' })).toBeChecked();
    expect(mock.gp.settings.set.mock.calls).toEqual([[{ theme: 'light' }], [{ theme: 'dark' }], [{ theme: 'system' }]]);
    expect(mock.gp.system.info).toHaveBeenCalledTimes(1); // no app reload
  });

  it('an explicit theme ignores OS changes, but "system" picks up the latest OS value immediately', async () => {
    const mock = installGpMock({ settings: { theme: 'light' }, info: { shouldUseDarkColors: false } });
    render(<App />);
    await waitFor(() => expect(root.dataset.theme).toBe('light'));
    mock.emitTheme(true); // OS switched to dark while the app forces light
    expect(root.dataset.theme).toBe('light');

    await openSettings();
    await pick('Системная');
    await waitFor(() => expect(root.dataset.theme).toBe('dark'));
    mock.emitTheme(false);
    expect(root.dataset.theme).toBe('light');
  });

  it('starts in the persisted explicit theme even when the OS reports the opposite', async () => {
    installGpMock({ settings: { theme: 'dark' }, info: { shouldUseDarkColors: false } });
    render(<App />);
    await waitFor(() => expect(root.dataset.theme).toBe('dark'));
  });
});

describe('onboarding routing', () => {
  it('without openconnect AND without profiles, installation comes first, then "add a portal"', async () => {
    const mock = installGpMock({ profiles: [], info: { openconnectFound: false } });
    render(<App />);
    expect(await screen.findByRole('heading', { name: 'Установите OpenConnect' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Добавьте портал' })).not.toBeInTheDocument();

    const found: SystemInfo = {
      platform: 'linux',
      openconnectFound: true,
      appVersion: '1',
      shouldUseDarkColors: false,
    };
    mock.gp.system.info.mockResolvedValue(found);
    await userEvent.click(screen.getByRole('button', { name: 'Проверить снова' }));
    expect(await screen.findByRole('heading', { name: 'Добавьте портал' })).toBeInTheDocument();
  });

  it('saving the first portal leaves onboarding for the connect screen with that profile', async () => {
    const mock = installGpMock({ profiles: [] });
    mock.gp.profiles.save.mockImplementation(async (p) => ({ ...p, id: PROFILE.id }));
    render(<App />);
    await screen.findByRole('heading', { name: 'Добавьте портал' });
    await userEvent.type(screen.getByLabelText('Название'), 'Офис');
    await userEvent.type(screen.getByLabelText('Адрес портала'), 'vpn.example.com');
    await userEvent.click(screen.getByRole('button', { name: 'Сохранить' }));

    expect(await screen.findByRole('button', { name: 'Подключить к Офис' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Добавьте портал' })).not.toBeInTheDocument();
  });

  it('other sections stay reachable during onboarding (e.g. Settings to set the openconnect path)', async () => {
    installGpMock({ profiles: [], info: { openconnectFound: false } });
    render(<App />);
    await screen.findByRole('heading', { name: 'Установите OpenConnect' });
    await userEvent.click(screen.getByRole('button', { name: 'Настройки' }));
    expect(await screen.findByRole('heading', { name: 'Настройки' })).toBeInTheDocument();
  });

  it('shows a retry when the initial data cannot be loaded, and recovers', async () => {
    const mock = installGpMock();
    mock.gp.settings.get.mockRejectedValueOnce(new Error('ipc down'));
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    render(<App />);
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Повторить' }));
    expect(await screen.findByRole('button', { name: 'Подключить к Работа' })).toBeInTheDocument();
    expect(mock.gp.settings.get).toHaveBeenCalledTimes(2);
    consoleError.mockRestore();
  });
});

describe('connect flow with auth prompts', () => {
  const PW: AuthPrompt = { id: '33333333-3333-4333-8333-333333333333', kind: 'password', message: 'Password:' };
  const OTP: AuthPrompt = {
    id: '44444444-4444-4444-8444-444444444444',
    kind: 'otp',
    message: 'Enter the 6-digit code\nChallenge',
  };

  it('Connect → password → OTP → Escape cancels with answerPrompt(id, null); no secret stays in the DOM', async () => {
    const user = userEvent.setup();
    const mock = installGpMock({ settings: { lastProfileId: PROFILE.id } });
    render(<App />);
    await user.click(await screen.findByRole('button', { name: 'Подключить к Работа' }));
    expect(mock.gp.vpn.connect).toHaveBeenCalledWith(PROFILE.id, undefined);

    mock.emitState({ status: 'authenticating', profileId: PROFILE.id });
    mock.emitPrompt(PW);
    const pwDialog = await screen.findByRole('dialog', { name: 'Вход' });
    expect(within(pwDialog).getByText('Профиль «Работа»')).toBeInTheDocument();
    await user.keyboard('Pa55-word{Enter}'); // focus starts in the field
    expect(mock.gp.vpn.answerPrompt).toHaveBeenCalledWith(PW.id, 'Pa55-word');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(document.body.innerHTML).not.toContain('Pa55-word');

    mock.emitPrompt(OTP);
    const otpDialog = await screen.findByRole('dialog', { name: 'Код подтверждения' });
    const otpField = within(otpDialog).getByLabelText('Challenge');
    expect(otpField).toHaveValue(''); // the previous answer is not carried over
    expect(otpField).toHaveFocus();
    expect(otpDialog).toHaveTextContent('Enter the 6-digit code');
    await user.keyboard('12');
    await user.keyboard('{Escape}');
    expect(mock.gp.vpn.answerPrompt).toHaveBeenLastCalledWith(OTP.id, null);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    // Focus returns to the control that started the flow (now "cancel connecting").
    expect(screen.getByRole('button', { name: 'Отменить подключение к Работа' })).toHaveFocus();
  });

  it('a prompt pushed while the pending-prompt snapshot is in flight wins over the older snapshot', async () => {
    const mock = installGpMock({ state: { status: 'authenticating', profileId: PROFILE.id } });
    let resolveSnapshot: (p: AuthPrompt[]) => void = () => undefined;
    mock.gp.vpn.getPendingPrompts.mockImplementation(() => new Promise((r) => (resolveSnapshot = r)));
    render(<App />);
    await waitFor(() => expect(mock.gp.vpn.getPendingPrompts).toHaveBeenCalled());

    mock.emitPrompt(OTP);
    resolveSnapshot([PW]); // stale: main has moved on to the OTP
    expect(await screen.findByRole('dialog', { name: 'Код подтверждения' })).toBeInTheDocument();
    await waitFor(() => expect(screen.getAllByRole('dialog')).toHaveLength(1));
    expect(screen.queryByRole('dialog', { name: 'Вход' })).not.toBeInTheDocument();
  });

  it('Tab keeps focus inside the dialog (focus trap)', async () => {
    const user = userEvent.setup();
    const mock = installGpMock({ state: { status: 'authenticating', profileId: PROFILE.id } });
    render(<App />);
    await waitFor(() => expect(mock.gp.vpn.onPrompt).toHaveBeenCalled());
    mock.emitPrompt(PW);
    const dialog = await screen.findByRole('dialog', { name: 'Вход' });
    for (let i = 0; i < 6; i++) {
      await user.tab();
      expect(dialog).toContainElement(document.activeElement as HTMLElement);
    }
    await user.tab({ shift: true });
    expect(dialog).toContainElement(document.activeElement as HTMLElement);
  });

  it('the dialog closes when the attempt fails while it is open', async () => {
    const mock = installGpMock({ state: { status: 'authenticating', profileId: PROFILE.id } });
    render(<App />);
    await waitFor(() => expect(mock.gp.vpn.onPrompt).toHaveBeenCalled());
    mock.emitPrompt(OTP);
    await screen.findByRole('dialog');
    mock.emitState({
      status: 'error',
      profileId: PROFILE.id,
      error: { code: 'PORTAL_UNREACHABLE', message: 'Портал недоступен' },
    });
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(mock.gp.vpn.answerPrompt).not.toHaveBeenCalled();
  });
});
