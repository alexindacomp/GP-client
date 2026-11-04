import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from '../../App';
import { installGpMock } from '../../test/gpMock';

describe('log screen', () => {
  it('shows the snapshot plus live lines, copies and opens the folder', async () => {
    const mock = installGpMock({ logs: ['line 1', 'line 2'] });
    const user = userEvent.setup(); // installs its own clipboard stub; replace it afterwards
    const writeText = vi.fn(async () => undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    render(<App />);
    await user.click(await screen.findByRole('button', { name: 'Журнал' }));
    expect(await screen.findByText('line 2')).toBeInTheDocument();
    mock.emitLine('line 3');
    expect(screen.getByText('line 3')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Копировать' }));
    expect(writeText).toHaveBeenCalledWith('line 1\nline 2\nline 3');
    await waitFor(() => expect(screen.getByRole('button', { name: 'Скопировано' })).toBeInTheDocument());

    await user.click(screen.getByRole('button', { name: 'Открыть папку логов' }));
    expect(mock.gp.logs.openFolder).toHaveBeenCalled();
    expect(screen.getByRole('checkbox', { name: 'Автопрокрутка' })).toBeChecked();
  });
});
