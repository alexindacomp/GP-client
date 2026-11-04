import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from '../../App';
import { installGpMock } from '../../test/gpMock';

describe('onboarding', () => {
  it('Windows: links to the OpenConnect-GUI releases (opened externally), winget only as a search hint', async () => {
    const mock = installGpMock({ info: { platform: 'win32', openconnectFound: false } });
    render(<App />);
    expect(await screen.findByRole('heading', { name: 'Установите OpenConnect' })).toBeInTheDocument();
    expect(screen.getByText(/Установите OpenConnect-GUI/)).toBeInTheDocument();
    expect(screen.getByText('winget search openconnect')).toBeInTheDocument();
    expect(screen.queryByText(/winget install/)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Скопировать команду winget search openconnect' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Открыть страницу загрузки OpenConnect-GUI' }));
    expect(mock.gp.system.openExternal).toHaveBeenCalledWith(
      'https://gitlab.com/openconnect/openconnect-gui/-/releases',
    );
  });

  it('macOS: recommends MacPorts, not Homebrew', async () => {
    installGpMock({ info: { platform: 'darwin', openconnectFound: false } });
    render(<App />);
    expect(await screen.findByText('sudo port install openconnect')).toBeInTheDocument();
    expect(screen.getByText(/Homebrew не подходит/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Установить MacPorts' })).toBeInTheDocument();
  });

  it('Linux: one copy button per command', async () => {
    const user = userEvent.setup();
    const writeText = vi.fn(async () => undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    installGpMock({ info: { platform: 'linux', openconnectFound: false } });
    render(<App />);
    await user.click(await screen.findByRole('button', { name: 'Скопировать команду sudo apt install openconnect' }));
    expect(writeText).toHaveBeenCalledWith('sudo apt install openconnect');
    expect(screen.getByRole('button', { name: 'Скопировать команду sudo apt update' })).toBeInTheDocument();
  });

  it('re-checks and leaves onboarding once openconnect is found', async () => {
    const mock = installGpMock({ info: { openconnectFound: false } });
    render(<App />);
    await screen.findByRole('heading', { name: 'Установите OpenConnect' });
    mock.gp.system.info.mockResolvedValueOnce({
      platform: 'linux',
      openconnectFound: true,
      appVersion: '1',
      shouldUseDarkColors: false,
    });
    await userEvent.click(screen.getByRole('button', { name: 'Проверить снова' }));
    expect(await screen.findByRole('button', { name: /Подключить/ })).toBeInTheDocument();
  });

  it('asks to add a portal when there are no profiles', async () => {
    installGpMock({ profiles: [] });
    render(<App />);
    expect(await screen.findByRole('heading', { name: 'Добавьте портал' })).toBeInTheDocument();
    expect(screen.getByLabelText('Адрес портала')).toBeInTheDocument();
  });
});
