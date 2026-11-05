import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { App } from '../../App';
import { installGpMock, PROFILE } from '../../test/gpMock';

async function openNewProfile() {
  const mock = installGpMock();
  render(<App />);
  await userEvent.click(await screen.findByRole('button', { name: 'Профили' }));
  await userEvent.click(screen.getByRole('button', { name: 'Добавить' }));
  await screen.findByRole('heading', { name: 'Новый профиль' });
  return mock;
}

describe('profile form', () => {
  it('shows required-field errors and does not save', async () => {
    const mock = await openNewProfile();
    await userEvent.click(screen.getByRole('button', { name: 'Сохранить' }));
    expect(screen.getByLabelText('Название')).toHaveAccessibleDescription('Введите название.');
    expect(screen.getByLabelText('Адрес портала')).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByText('Введите адрес портала.')).toBeInTheDocument();
    expect(screen.getByLabelText('Название')).toHaveFocus();
    expect(mock.gp.profiles.save).not.toHaveBeenCalled();
  });

  it('rejects http:// portals', async () => {
    const mock = await openNewProfile();
    await userEvent.type(screen.getByLabelText('Название'), 'Офис');
    await userEvent.type(screen.getByLabelText('Адрес портала'), 'http://vpn.example.com');
    await userEvent.click(screen.getByRole('button', { name: 'Сохранить' }));
    expect(screen.getByText('Поддерживаются только порталы https://.')).toBeInTheDocument();
    expect(mock.gp.profiles.save).not.toHaveBeenCalled();
  });

  it('saves a normalized https://host[:port] URL and returns to the list', async () => {
    const mock = await openNewProfile();
    await userEvent.type(screen.getByLabelText('Название'), ' Офис ');
    await userEvent.type(screen.getByLabelText('Адрес портала'), 'vpn.corp.test:4443/global-protect');
    expect(screen.getByText('Будет использован https://vpn.corp.test:4443')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('checkbox', { name: 'Запомнить пароль' }));
    await userEvent.type(screen.getByLabelText(/^Пароль/), 'pw');
    await userEvent.click(screen.getByRole('button', { name: 'Сохранить' }));
    expect(mock.gp.profiles.save).toHaveBeenCalledWith(
      { name: 'Офис', portalUrl: 'https://vpn.corp.test:4443', authMode: 'auto', savePassword: true },
      'pw',
    );
    expect(await screen.findByRole('heading', { name: 'Профили' })).toBeInTheDocument();
    expect(screen.getByText('Офис')).toBeInTheDocument();
  });

  it('never stores a password for SAML', async () => {
    const mock = await openNewProfile();
    await userEvent.type(screen.getByLabelText('Название'), 'SSO');
    await userEvent.type(screen.getByLabelText('Адрес портала'), 'sso.example.com');
    await userEvent.selectOptions(screen.getByLabelText('Способ входа'), 'saml');
    expect(screen.getByRole('checkbox', { name: /Запомнить пароль/ })).toBeDisabled();
    await userEvent.click(screen.getByRole('button', { name: 'Сохранить' }));
    expect(mock.gp.profiles.save).toHaveBeenCalledWith(
      { name: 'SSO', portalUrl: 'https://sso.example.com', authMode: 'saml', savePassword: false },
      undefined,
    );
  });

  it('routes a marked main-process rejection to its field', async () => {
    const mock = await openNewProfile();
    mock.gp.profiles.save.mockRejectedValueOnce(new Error('[field:portalUrl][code:credentials] no creds'));
    await userEvent.type(screen.getByLabelText('Название'), 'X');
    await userEvent.type(screen.getByLabelText('Адрес портала'), 'vpn.example.com');
    await userEvent.click(screen.getByRole('button', { name: 'Сохранить' }));
    await waitFor(() =>
      expect(screen.getByLabelText('Адрес портала')).toHaveAccessibleDescription(
        expect.stringContaining('Адрес не должен содержать логин или пароль.'),
      ),
    );
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('shows the main-process rejection message', async () => {
    const mock = await openNewProfile();
    mock.gp.profiles.save.mockRejectedValueOnce(new Error('name is too long (max 100)'));
    await userEvent.type(screen.getByLabelText('Название'), 'X');
    await userEvent.type(screen.getByLabelText('Адрес портала'), 'vpn.example.com');
    await userEvent.click(screen.getByRole('button', { name: 'Сохранить' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Не удалось сохранить: name is too long (max 100)');
  });

  it('deletes a profile after confirmation (mentions SSO cookies)', async () => {
    const mock = installGpMock();
    render(<App />);
    await userEvent.click(await screen.findByRole('button', { name: 'Профили' }));
    await userEvent.click(screen.getByRole('button', { name: 'Удалить профиль Работа' }));
    const dialog = await screen.findByRole('alertdialog', { name: 'Удалить профиль?' });
    expect(dialog).toHaveTextContent(/SSO/);
    expect(within(dialog).getByRole('button', { name: 'Отмена' })).toHaveFocus();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Удалить' }));
    expect(mock.gp.profiles.remove).toHaveBeenCalledWith(PROFILE.id);
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(screen.getByText('Профилей пока нет.')).toBeInTheDocument();
  });

  it('cannot delete the profile that is connected', async () => {
    installGpMock({ state: { status: 'connected', profileId: PROFILE.id } });
    render(<App />);
    await userEvent.click(await screen.findByRole('button', { name: 'Профили' }));
    expect(await screen.findByText('Используется')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Удалить профиль Работа' })).toBeDisabled();
  });
});
