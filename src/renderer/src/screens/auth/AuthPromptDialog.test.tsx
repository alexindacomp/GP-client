import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { App } from '../../App';
import { installGpMock, PROFILE, type GpMock } from '../../test/gpMock';

const PROMPT_ID = '22222222-2222-4222-8222-222222222222';

async function setup(profile = PROFILE): Promise<GpMock> {
  const mock = installGpMock({ profiles: [profile], state: { status: 'authenticating', profileId: profile.id } });
  render(<App />);
  await screen.findByRole('heading', { name: 'Подключение' });
  await waitFor(() => expect(mock.gp.vpn.onPrompt).toHaveBeenCalled());
  mock.emitState({ status: 'authenticating', profileId: profile.id });
  return mock;
}

describe('auth prompt dialog', () => {
  it('shows a prompt that was already pending before the UI mounted (renderer reload)', async () => {
    const mock = installGpMock({
      state: { status: 'authenticating', profileId: PROFILE.id },
      pendingPrompts: [{ id: PROMPT_ID, kind: 'otp', message: 'Code' }],
    });
    render(<App />);
    expect(await screen.findByRole('dialog', { name: 'Код подтверждения' })).toBeInTheDocument();
    // The backend also re-pushes it after a reload: the same id must not reset the dialog.
    await userEvent.type(screen.getByLabelText('Code'), '123');
    mock.emitPrompt({ id: PROMPT_ID, kind: 'otp', message: 'Code' });
    expect(screen.getByLabelText('Code')).toHaveValue('123');
    expect(mock.gp.vpn.onPrompt.mock.invocationCallOrder[0]).toBeLessThan(
      mock.gp.vpn.getPendingPrompts.mock.invocationCallOrder[0]!,
    );
  });

  it('submits a password with the label taken from the last message line', async () => {
    const mock = await setup();
    mock.emitPrompt({ id: PROMPT_ID, kind: 'password', message: 'Welcome to ACME\nPassword:' });
    const dialog = await screen.findByRole('dialog', { name: 'Вход' });
    expect(dialog).toHaveTextContent('Welcome to ACME');
    const input = screen.getByLabelText('Password:');
    expect(input).toHaveAttribute('type', 'password');
    expect(input).toHaveFocus();
    await userEvent.type(input, 's3cret{Enter}');
    expect(mock.gp.vpn.answerPrompt).toHaveBeenCalledWith(PROMPT_ID, 's3cret');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('requires a value before submitting', async () => {
    const mock = await setup();
    mock.emitPrompt({ id: PROMPT_ID, kind: 'otp', message: 'Code' });
    await screen.findByRole('dialog', { name: 'Код подтверждения' });
    await userEvent.click(screen.getByRole('button', { name: 'Продолжить' }));
    expect(screen.getByText('Введите значение.')).toBeInTheDocument();
    expect(mock.gp.vpn.answerPrompt).not.toHaveBeenCalled();
  });

  it('cancel answers null', async () => {
    const mock = await setup();
    mock.emitPrompt({ id: PROMPT_ID, kind: 'otp', message: 'Enter the code\nOTP' });
    await screen.findByRole('dialog');
    await userEvent.click(screen.getByRole('button', { name: 'Отмена' }));
    expect(mock.gp.vpn.answerPrompt).toHaveBeenCalledWith(PROMPT_ID, null);
  });

  it('Escape answers null', async () => {
    const mock = await setup();
    mock.emitPrompt({ id: PROMPT_ID, kind: 'text', message: 'Username' });
    await screen.findByRole('dialog');
    await userEvent.keyboard('{Escape}');
    expect(mock.gp.vpn.answerPrompt).toHaveBeenCalledWith(PROMPT_ID, null);
  });

  it('select prompt answers the chosen option', async () => {
    const mock = await setup();
    mock.emitPrompt({ id: PROMPT_ID, kind: 'select', message: 'Choose group\nGROUP:', options: ['Staff', 'IT'] });
    await screen.findByRole('dialog', { name: 'Выберите вариант' });
    await userEvent.click(screen.getByRole('radio', { name: 'IT' }));
    await userEvent.click(screen.getByRole('button', { name: 'Продолжить' }));
    expect(mock.gp.vpn.answerPrompt).toHaveBeenCalledWith(PROMPT_ID, 'IT');
  });

  it('closes when the attempt ends without an answer', async () => {
    const mock = await setup();
    mock.emitPrompt({ id: PROMPT_ID, kind: 'password', message: 'Password' });
    await screen.findByRole('dialog');
    mock.emitState({ status: 'error', profileId: PROFILE.id, error: { code: 'AUTH_CANCELLED', message: 'x' } });
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('"remember password" saves the password only after the connection succeeds', async () => {
    const mock = await setup();
    mock.emitPrompt({ id: PROMPT_ID, kind: 'password', message: 'Password' });
    await screen.findByRole('dialog');
    await userEvent.type(screen.getByLabelText('Password'), 'pw');
    await userEvent.click(screen.getByRole('checkbox', { name: /Запомнить пароль/ }));
    await userEvent.click(screen.getByRole('button', { name: 'Войти' }));
    expect(mock.gp.vpn.answerPrompt).toHaveBeenCalledWith(PROMPT_ID, 'pw');
    expect(mock.gp.profiles.save).not.toHaveBeenCalled();

    mock.emitState({ status: 'connected', profileId: PROFILE.id });
    await waitFor(() => expect(mock.gp.profiles.save).toHaveBeenCalledWith({ ...PROFILE, savePassword: true }, 'pw'));
  });

  it('"remember password" is dropped when sign-in fails', async () => {
    const mock = await setup();
    mock.emitPrompt({ id: PROMPT_ID, kind: 'password', message: 'Password' });
    await screen.findByRole('dialog');
    await userEvent.type(screen.getByLabelText('Password'), 'wrong');
    await userEvent.click(screen.getByRole('checkbox', { name: /Запомнить пароль/ }));
    await userEvent.click(screen.getByRole('button', { name: 'Войти' }));
    mock.emitState({ status: 'error', profileId: PROFILE.id, error: { code: 'AUTH_FAILED', message: 'x' } });
    mock.emitState({ status: 'connected', profileId: PROFILE.id });
    expect(mock.gp.profiles.save).not.toHaveBeenCalled();
  });

  it('does not offer "remember" for OTP prompts or SAML profiles', async () => {
    const mock = await setup({ ...PROFILE, authMode: 'saml' });
    mock.emitPrompt({ id: PROMPT_ID, kind: 'password', message: 'Password' });
    await screen.findByRole('dialog');
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
  });
});
