import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { App } from '../../App';
import { DEFAULT_SETTINGS } from '@shared/ipc';
import { installGpMock } from '../../test/gpMock';

async function openSettings(settings = {}) {
  const mock = installGpMock({ settings });
  render(<App />);
  await userEvent.click(await screen.findByRole('button', { name: 'Настройки' }));
  return mock;
}

describe('openconnect settings', () => {
  it('rejects a relative openconnect path locally', async () => {
    const mock = await openSettings();
    await userEvent.type(screen.getByLabelText('Путь к openconnect'), 'bin/openconnect');
    await userEvent.click(screen.getByRole('button', { name: 'Сохранить' }));
    expect(screen.getByText('Укажите абсолютный путь.')).toBeInTheDocument();
    expect(mock.gp.settings.set).not.toHaveBeenCalled();
  });

  it('rejects a path that is not the openconnect binary', async () => {
    const mock = await openSettings();
    await userEvent.type(screen.getByLabelText('Путь к openconnect'), '/usr/bin/bash');
    expect(screen.getByLabelText('Путь к openconnect')).toHaveAccessibleDescription(
      expect.stringContaining('Путь должен указывать на файл openconnect'),
    );
    await userEvent.click(screen.getByRole('button', { name: 'Сохранить' }));
    expect(mock.gp.settings.set).not.toHaveBeenCalled();
  });

  it('rejects options outside the allowlist inline', async () => {
    const mock = await openSettings();
    await userEvent.type(screen.getByLabelText('Дополнительные аргументы'), '--script=/tmp/x');
    expect(screen.getByLabelText('Дополнительные аргументы')).toHaveAccessibleDescription(
      expect.stringContaining('Опция «--script» не разрешена.'),
    );
    await userEvent.click(screen.getByRole('button', { name: 'Сохранить' }));
    expect(mock.gp.settings.set).not.toHaveBeenCalled();
  });

  it('sends only changed fields and re-detects openconnect after a path change', async () => {
    const mock = await openSettings();
    await userEvent.type(screen.getByLabelText('Путь к openconnect'), '/usr/sbin/openconnect');
    await userEvent.type(screen.getByLabelText('Дополнительные аргументы'), '--no-dtls');
    mock.gp.system.info.mockClear();
    await userEvent.click(screen.getByRole('button', { name: 'Сохранить' }));
    expect(mock.gp.settings.set).toHaveBeenCalledWith({
      openconnectPath: '/usr/sbin/openconnect',
      extraArgs: ['--no-dtls'],
    });
    await waitFor(() => expect(mock.gp.system.info).toHaveBeenCalled());
    expect(await screen.findByText('Сохранено')).toBeInTheDocument();
  });

  it('shows a pending state while main waits for confirmation, then reverts if not confirmed', async () => {
    const mock = await openSettings({ openconnectPath: '/usr/bin/openconnect' });
    let reject!: (e: Error) => void;
    mock.gp.settings.set.mockImplementationOnce(() => new Promise((_, r) => (reject = r)));
    const field = screen.getByLabelText('Путь к openconnect');
    await userEvent.clear(field);
    await userEvent.type(field, '/opt/oc/openconnect');
    await userEvent.click(screen.getByRole('button', { name: 'Сохранить' }));
    expect(screen.getByRole('button', { name: 'Сохранение…' })).toBeDisabled();
    expect(screen.getByText('Подтвердите изменение в системном окне.')).toBeInTheDocument();

    reject(
      new Error(
        "Error invoking remote method 'gp:settings:set': Error: [code:not_confirmed] The change was not confirmed",
      ),
    );
    expect(await screen.findByText('Изменение не подтверждено, прежние значения восстановлены.')).toBeInTheDocument();
    expect(field).toHaveValue('/usr/bin/openconnect');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('shows a marked extraArgs rejection under that field', async () => {
    const mock = await openSettings();
    mock.gp.settings.set.mockRejectedValueOnce(
      new Error(
        'Error invoking remote method \'gp:settings:set\': Error: [field:extraArgs][code:not_allowed] Option "--mtu" is not allowed',
      ),
    );
    await userEvent.type(screen.getByLabelText('Дополнительные аргументы'), '--mtu=1300');
    await userEvent.click(screen.getByRole('button', { name: 'Сохранить' }));
    await waitFor(() =>
      expect(screen.getByLabelText('Дополнительные аргументы')).toHaveAccessibleDescription(
        expect.stringContaining('Одна из опций не разрешена.'),
      ),
    );
  });

  it('routes a marked openconnectPath rejection to that field with localized text', async () => {
    const mock = await openSettings();
    mock.gp.settings.set.mockRejectedValueOnce(
      new Error(
        "Error invoking remote method 'gp:settings:set': Error: [field:openconnectPath][code:not_openconnect] openconnectPath must point to the openconnect binary",
      ),
    );
    await userEvent.type(screen.getByLabelText('Путь к openconnect'), '/usr/sbin/openconnect');
    await userEvent.click(screen.getByRole('button', { name: 'Сохранить' }));
    await waitFor(() =>
      expect(screen.getByLabelText('Путь к openconnect')).toHaveAccessibleDescription(
        expect.stringContaining('Путь должен указывать на файл openconnect'),
      ),
    );
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('lists the allowed extra options as chips', async () => {
    await openSettings();
    expect(screen.getByText('--servercert=…', { selector: 'code' })).toBeInTheDocument();
    expect(screen.getByText('--no-dtls', { selector: 'code' })).toBeInTheDocument();
  });

  it('applies quick successive setting clicks (no double-submit guard)', async () => {
    const mock = await openSettings();
    let release!: () => void;
    mock.gp.settings.set.mockImplementationOnce(
      (patch) =>
        new Promise((resolve) => {
          release = () => resolve({ ...DEFAULT_SETTINGS, ...patch });
        }),
    );
    await userEvent.click(screen.getByRole('radio', { name: 'Тёмная' }));
    await userEvent.click(screen.getByRole('switch', { name: 'Переподключаться при обрыве' }));
    expect(mock.gp.settings.set).toHaveBeenCalledWith({ theme: 'dark' });
    expect(mock.gp.settings.set).toHaveBeenCalledWith({ autoReconnect: false });
    release();
  });

  it('shows the version without a leading "v" and the detected binary as the path placeholder', async () => {
    installGpMock({
      info: { openconnectVersion: 'v9.12', openconnectPath: '/usr/sbin/openconnect', openconnectTrusted: true },
    });
    render(<App />);
    await userEvent.click(await screen.findByRole('button', { name: 'Настройки' }));
    expect(screen.getByText('Найден, версия 9.12')).toBeInTheDocument();
    expect(screen.getByLabelText('Путь к openconnect')).toHaveAttribute('placeholder', '/usr/sbin/openconnect');
  });

  it('warns when openconnect is found in an unprotected folder', async () => {
    installGpMock({
      info: {
        platform: 'darwin',
        openconnectPath: '/opt/homebrew/bin/openconnect',
        openconnectTrusted: false,
      },
    });
    render(<App />);
    await userEvent.click(await screen.findByRole('button', { name: 'Настройки' }));
    expect(screen.getByText('Найден, но в незащищённой папке: /opt/homebrew/bin/openconnect')).toBeInTheDocument();
    expect(screen.queryByText(/Найден, версия/)).not.toBeInTheDocument();
    expect(screen.getByText('sudo port install openconnect', { selector: 'code' })).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Скопировать команду sudo port install openconnect' }),
    ).toBeInTheDocument();
  });

  it('toggles behaviour switches', async () => {
    const mock = await openSettings();
    await userEvent.click(screen.getByRole('switch', { name: 'Подключаться при запуске' }));
    expect(mock.gp.settings.set).toHaveBeenCalledWith({ connectOnStartup: true });
  });
});
