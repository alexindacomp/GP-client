import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { VpnErrorCode, VpnErrorHint, VpnState } from '@shared/ipc';
import { App } from '../../App';
import { installGpMock, PROFILE, type GpMock } from '../../test/gpMock';

let mock: GpMock;

async function renderWith(state: VpnState): Promise<void> {
  mock = installGpMock({ state, settings: { lastProfileId: PROFILE.id } });
  render(<App />);
  await screen.findByRole('heading', { name: 'Подключение' });
  await waitFor(() => expect(mock.gp.vpn.getState).toHaveBeenCalled());
}

describe('connect toggle', () => {
  beforeEach(() => {
    mock = installGpMock();
  });

  it('connects the selected profile when disconnected', async () => {
    await renderWith({ status: 'disconnected' });
    await userEvent.click(await screen.findByRole('button', { name: 'Подключить к Работа' }));
    expect(mock.gp.vpn.connect).toHaveBeenCalledWith(PROFILE.id, undefined);
  });

  it('passes the chosen gateway', async () => {
    await renderWith({
      status: 'disconnected',
      profileId: PROFILE.id,
      gateways: [{ name: 'gw-2', address: 'gw2.example.com' }],
    });
    await userEvent.selectOptions(screen.getByLabelText('Шлюз'), 'gw-2');
    await userEvent.click(screen.getByRole('button', { name: 'Подключить к Работа' }));
    expect(mock.gp.vpn.connect).toHaveBeenCalledWith(PROFILE.id, { gateway: 'gw-2' });
  });

  it('disconnects when connected and shows IP, gateway and duration (no traffic stats)', async () => {
    await renderWith({
      status: 'connected',
      profileId: PROFILE.id,
      assignedIp: '10.0.0.7',
      gateway: { name: 'gw-1', address: 'gw1.example.com' },
      connectedAt: Date.now() - 65_000,
    });
    expect(await screen.findByText('10.0.0.7')).toBeInTheDocument();
    expect(screen.getByText('gw-1', { selector: 'dd' })).toBeInTheDocument();
    expect(screen.getByText('Время подключения')).toBeInTheDocument();
    expect(screen.getByText(/^1:0\d$/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Отключить от Работа' }));
    expect(mock.gp.vpn.disconnect).toHaveBeenCalled();
    expect(mock.gp.vpn.connect).not.toHaveBeenCalled();
  });

  it('cancels a running attempt and locks the pickers', async () => {
    await renderWith({ status: 'authenticating', profileId: PROFILE.id });
    expect(screen.getByLabelText('Профиль')).toBeDisabled();
    await userEvent.click(await screen.findByRole('button', { name: 'Отменить подключение к Работа' }));
    expect(mock.gp.vpn.disconnect).toHaveBeenCalled();
  });

  it('is inert while disconnecting', async () => {
    await renderWith({ status: 'connected', profileId: PROFILE.id });
    mock.emitState({ status: 'disconnecting', profileId: PROFILE.id });
    expect(await screen.findByRole('button', { name: 'Отключение…' })).toBeDisabled();
  });

  it('follows live state updates', async () => {
    await renderWith({ status: 'disconnected' });
    mock.emitState({ status: 'connecting', profileId: PROFILE.id });
    expect(within(screen.getByRole('status')).getByText('Установка туннеля')).toBeInTheDocument();
    mock.emitState({ status: 'connected', profileId: PROFILE.id, assignedIp: '10.1.1.1', connectedAt: Date.now() });
    expect(await screen.findByText('10.1.1.1')).toBeInTheDocument();
  });

  it('shows a connect rejection from the backend', async () => {
    await renderWith({ status: 'disconnected' });
    mock.gp.vpn.connect.mockRejectedValueOnce(new Error('[code:busy] Cannot connect while connecting'));
    await userEvent.click(screen.getByRole('button', { name: 'Подключить к Работа' }));
    expect(await screen.findByText('Дождитесь завершения текущей операции.')).toBeInTheDocument();
  });
});

describe('error banner', () => {
  const errorState = (code: VpnErrorCode, message = `msg ${code}`): VpnState => ({
    status: 'error',
    profileId: PROFILE.id,
    error: { code, message },
  });

  it.each<[VpnErrorCode, string, string[]]>([
    ['OPENCONNECT_NOT_FOUND', 'OpenConnect не найден', ['Указать путь к openconnect', 'Повторить']],
    ['AUTH_FAILED', 'Ошибка входа', ['Повторить', 'Изменить профиль']],
    ['PORTAL_UNREACHABLE', 'Портал недоступен', ['Повторить', 'Изменить профиль']],
    ['TLS_ERROR', 'Сертификат сервера не прошёл проверку', ['Открыть настройки', 'Открыть журнал']],
    ['PRIVILEGES_DENIED', 'Нет прав администратора', ['Открыть настройки', 'Повторить']],
    ['TUNNEL_FAILED', 'Не удалось создать туннель', ['Повторить', 'Открыть журнал']],
    ['UNKNOWN', 'Ошибка подключения', ['Повторить', 'Открыть журнал']],
  ])('%s is an alert with its title, message and actions', async (code, title, actions) => {
    await renderWith(errorState(code));
    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText(title)).toBeInTheDocument();
    expect(within(alert).getByText(`msg ${code}`)).toBeInTheDocument();
    for (const name of actions) expect(within(alert).getByRole('button', { name })).toBeInTheDocument();
  });

  it('shows a cancelled sign-in softly (status, not alert) with only "retry"', async () => {
    await renderWith(errorState('AUTH_CANCELLED'));
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect((await screen.findAllByText('Вход отменён')).length).toBeGreaterThan(0);
    expect(screen.queryByText('msg AUTH_CANCELLED')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Повторить' })).toBeInTheDocument();
  });

  it('shows the error title in the status line and the technical detail behind a disclosure', async () => {
    await renderWith({
      status: 'error',
      profileId: PROFILE.id,
      error: { code: 'TUNNEL_FAILED', message: 'Попробуйте снова.', detail: 'vpnc-script exited with status 1' },
    });
    const alert = await screen.findByRole('alert');
    const statusLine = screen
      .getAllByRole('status')
      .find((el) => el.textContent?.includes('Не удалось создать туннель'));
    expect(statusLine).toBeDefined();
    expect(within(alert).getByText('Попробуйте снова.')).toBeInTheDocument();
    // The technical detail is collapsed behind a disclosure so the banner stays short.
    const disclosure = within(alert).getByRole('button', { name: 'Подробности' });
    expect(disclosure).toHaveAttribute('aria-expanded', 'false');
    expect(within(alert).getByText('vpnc-script exited with status 1')).not.toBeVisible();
    await userEvent.click(disclosure);
    expect(disclosure).toHaveAttribute('aria-expanded', 'true');
    expect(within(alert).getByText('vpnc-script exited with status 1')).toBeVisible();
  });

  it('renders the error banner above the toggle so its actions stay visible', async () => {
    await renderWith(errorState('PRIVILEGES_DENIED'));
    const alert = await screen.findByRole('alert');
    const toggle = screen.getByRole('button', { name: 'Подключить к Работа' });
    expect(alert.compareDocumentPosition(toggle) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('keeps Disconnect available when openconnect could not be stopped', async () => {
    await renderWith({
      status: 'connected',
      profileId: PROFILE.id,
      error: { code: 'PRIVILEGES_DENIED', message: 'Нажмите «Отключить» ещё раз.' },
    });
    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText('Не удалось отключиться')).toBeInTheDocument();
    expect(within(alert).getByText('Нажмите «Отключить» ещё раз.')).toBeInTheDocument();
    await userEvent.click(within(alert).getByRole('button', { name: 'Отключить' }));
    expect(mock.gp.vpn.disconnect).toHaveBeenCalledTimes(1);
    // The (compact) toggle keeps its full accessible name.
    expect(screen.getByRole('button', { name: 'Отключить от Работа' })).toBeInTheDocument();
  });

  it('renders a --servercert pin hint as code, keeping trailing punctuation outside', async () => {
    const pin = `${'A'.repeat(43)}=`;
    await renderWith({
      status: 'error',
      profileId: PROFILE.id,
      error: {
        code: 'TLS_ERROR',
        message: `Добавьте --servercert=pin-sha256:<…> — или --servercert=pin-sha256:${pin}.`,
      },
    });
    const alert = await screen.findByRole('alert');
    const codes = alert.querySelectorAll('code');
    expect([...codes].map((c) => c.textContent)).toEqual([
      '--servercert=pin-sha256:<…>',
      `--servercert=pin-sha256:${pin}`,
    ]);
    expect(codes[1]!.querySelector('wbr')).not.toBeNull();
    expect(codes[1]!.nextSibling?.textContent).toBe('.');
  });

  it('renders an install command in the message as code with a copy button', async () => {
    const user = userEvent.setup();
    const writeText = vi.fn(async () => undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    await renderWith({
      status: 'error',
      profileId: PROFILE.id,
      error: {
        code: 'PRIVILEGES_DENIED',
        hint: 'untrusted_homebrew',
        message: 'Установите его через MacPorts: sudo port install openconnect.',
      },
    });
    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText('sudo port install openconnect').tagName).toBe('CODE');
    await user.click(within(alert).getByRole('button', { name: 'Скопировать команду sudo port install openconnect' }));
    expect(writeText).toHaveBeenCalledWith('sudo port install openconnect');
  });

  it('"retry" reconnects the same profile', async () => {
    await renderWith(errorState('AUTH_FAILED'));
    await userEvent.click(within(await screen.findByRole('alert')).getByRole('button', { name: 'Повторить' }));
    expect(mock.gp.vpn.connect).toHaveBeenCalledWith(PROFILE.id, undefined);
  });

  it('"set path" opens settings with the openconnect path focused', async () => {
    await renderWith(errorState('OPENCONNECT_NOT_FOUND'));
    await userEvent.click(await screen.findByRole('button', { name: 'Указать путь к openconnect' }));
    expect(await screen.findByLabelText('Путь к openconnect')).toHaveFocus();
  });

  it.each<[VpnErrorHint, string]>([
    ['untrusted_binary', 'OpenConnect в незащищённой папке'],
    ['untrusted_homebrew', 'OpenConnect в незащищённой папке'],
    ['settings_not_confirmed', 'Изменения не подтверждены'],
  ])('titles the error by its hint (%s)', async (hint, title) => {
    await renderWith({
      status: 'error',
      profileId: PROFILE.id,
      error: { code: 'PRIVILEGES_DENIED', hint, message: 'next step' },
    });
    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText(title)).toBeInTheDocument();
    expect(within(alert).queryByText('Нет прав администратора')).not.toBeInTheDocument();
    expect(screen.getAllByText(title)).toHaveLength(2); // banner + status line
  });

  it('"open settings" scrolls to the OpenConnect section and focuses the path field', async () => {
    const scrollIntoView = vi.fn();
    Element.prototype.scrollIntoView = scrollIntoView;
    await renderWith({
      status: 'error',
      profileId: PROFILE.id,
      error: { code: 'PRIVILEGES_DENIED', hint: 'untrusted_binary', message: 'x' },
    });
    await userEvent.click(within(await screen.findByRole('alert')).getByRole('button', { name: 'Открыть настройки' }));
    const field = await screen.findByLabelText('Путь к openconnect');
    expect(field).toHaveFocus();
    const heading = screen.getByRole('heading', { name: 'OpenConnect' });
    expect(scrollIntoView.mock.contexts).toContain(heading);
  });

  it('"edit profile" opens the profile editor', async () => {
    await renderWith(errorState('PORTAL_UNREACHABLE'));
    await userEvent.click(await screen.findByRole('button', { name: 'Изменить профиль' }));
    expect(await screen.findByRole('heading', { name: 'Изменить профиль' })).toBeInTheDocument();
    expect(screen.getByLabelText('Адрес портала')).toHaveValue(PROFILE.portalUrl);
  });

  it('can be dismissed', async () => {
    await renderWith(errorState('UNKNOWN'));
    await userEvent.click(within(await screen.findByRole('alert')).getByRole('button', { name: 'Скрыть' }));
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('shows the drop reason while reconnecting', async () => {
    await renderWith({
      status: 'reconnecting',
      profileId: PROFILE.id,
      error: { code: 'TUNNEL_FAILED', message: 'Попробуйте позже.', detail: 'DPD timeout' },
    });
    expect(await screen.findByText('Соединение прервано')).toBeInTheDocument();
    expect(screen.getByText('Переподключаемся автоматически. Подробности — в журнале.')).toBeInTheDocument();
    expect(screen.queryByText('Попробуйте позже.')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Подробности' }));
    expect(screen.getByText('DPD timeout')).toBeVisible();
  });
});
