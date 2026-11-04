import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it } from 'vitest';
import { App } from '../App';
import { installGpMock } from '../test/gpMock';
import { resolveTheme } from './useTheme';

const root = document.documentElement;

afterEach(() => {
  delete root.dataset.theme;
  delete root.dataset.platform;
});

describe('theme', () => {
  it('resolves explicit choices and follows the OS for "system"', () => {
    expect(resolveTheme('light', true)).toBe('light');
    expect(resolveTheme('dark', false)).toBe('dark');
    expect(resolveTheme('system', true)).toBe('dark');
    expect(resolveTheme('system', false)).toBe('light');
  });

  it('applies data-theme and data-platform from settings and system info', async () => {
    installGpMock({ settings: { theme: 'system' }, info: { shouldUseDarkColors: true, platform: 'win32' } });
    render(<App />);
    await waitFor(() => expect(root.dataset.theme).toBe('dark'));
    expect(root.dataset.platform).toBe('win32');
  });

  it('follows OS theme changes in "system" mode instantly', async () => {
    const mock = installGpMock({ settings: { theme: 'system' } });
    render(<App />);
    await waitFor(() => expect(root.dataset.theme).toBe('light'));
    mock.emitTheme(true);
    expect(root.dataset.theme).toBe('dark');
  });

  it('switches immediately when the user picks a theme in Settings', async () => {
    const mock = installGpMock({ settings: { theme: 'system' } });
    render(<App />);
    await userEvent.click(await screen.findByRole('button', { name: 'Настройки' }));
    await userEvent.click(screen.getByRole('radio', { name: 'Тёмная' }));
    expect(mock.gp.settings.set).toHaveBeenCalledWith({ theme: 'dark' });
    await waitFor(() => expect(root.dataset.theme).toBe('dark'));
    // An explicit theme ignores OS reports.
    mock.emitTheme(false);
    expect(root.dataset.theme).toBe('dark');
  });

  it.each([
    ['en', 'Settings'],
    ['uk', 'Налаштування'],
  ])('switches language to %s from Settings', async (lang, heading) => {
    const mock = installGpMock();
    render(<App />);
    await userEvent.click(await screen.findByRole('button', { name: 'Настройки' }));
    const select = screen.getByLabelText('Язык');
    expect([...(select as HTMLSelectElement).options].map((o) => o.text)).toEqual(['Русский', 'English', 'Українська']);
    await userEvent.selectOptions(select, lang);
    expect(mock.gp.settings.set).toHaveBeenCalledWith({ language: lang });
    expect(await screen.findByRole('heading', { name: heading })).toBeInTheDocument();
    expect(root.lang).toBe(lang);
  });
});
