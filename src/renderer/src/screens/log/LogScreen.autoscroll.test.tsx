import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from '../../App';
import { installGpMock, type GpMock } from '../../test/gpMock';

const LINE_PX = 20;
const VIEW_PX = 100;

/**
 * jsdom has no layout: give the log viewport a geometry derived from its content
 * (LINE_PX per rendered line, VIEW_PX visible) and a writable scrollTop.
 */
function withGeometry(el: HTMLElement): { readonly maxScroll: number } {
  let top = 0;
  const height = (): number => Math.max(el.childElementCount * LINE_PX, VIEW_PX);
  Object.defineProperties(el, {
    scrollHeight: { configurable: true, get: height },
    clientHeight: { configurable: true, get: () => VIEW_PX },
    scrollTop: {
      configurable: true,
      get: () => top,
      set: (v: number) => {
        top = Math.max(0, Math.min(v, height() - VIEW_PX));
      },
    },
  });
  return {
    get maxScroll() {
      return height() - VIEW_PX;
    },
  };
}

async function openLog(
  lines: number,
): Promise<{ mock: GpMock; log: HTMLElement; geo: { readonly maxScroll: number } }> {
  const mock = installGpMock({ logs: Array.from({ length: lines }, (_, i) => `line ${i + 1}`) });
  render(<App />);
  await userEvent.click(await screen.findByRole('button', { name: 'Журнал' }));
  await screen.findByText(`line ${lines}`);
  const log = screen.getByRole('log', { name: 'Журнал событий' });
  const geo = withGeometry(log);
  return { mock, log, geo };
}

const userScrollsTo = (el: HTMLElement, top: number): void => {
  el.scrollTop = top;
  fireEvent.scroll(el);
};

describe('log screen auto-scroll', () => {
  it('follows new lines while at the bottom', async () => {
    const { mock, log, geo } = await openLog(10);
    mock.emitLine('line 11');
    expect(log.scrollTop).toBe(geo.maxScroll);
    expect(log.scrollTop).toBeGreaterThan(0);
  });

  it('scrolling up pauses it (checkbox unchecked) and new lines do not move the view', async () => {
    const { mock, log } = await openLog(10);
    mock.emitLine('line 11');
    userScrollsTo(log, 40);
    expect(screen.getByRole('checkbox', { name: 'Автопрокрутка' })).not.toBeChecked();

    mock.emitLine('line 12');
    mock.emitLine('line 13');
    expect(screen.getByText('line 13')).toBeInTheDocument();
    expect(log.scrollTop).toBe(40);
  });

  it('scrolling back to the end resumes following', async () => {
    const { mock, log, geo } = await openLog(10);
    mock.emitLine('line 11');
    userScrollsTo(log, 0);
    mock.emitLine('line 12');
    userScrollsTo(log, geo.maxScroll - 4); // within the 8 px "at bottom" tolerance
    expect(screen.getByRole('checkbox', { name: 'Автопрокрутка' })).toBeChecked();

    mock.emitLine('line 13');
    expect(log.scrollTop).toBe(geo.maxScroll);
  });

  it('the checkbox pauses and resumes; resuming jumps to the newest line', async () => {
    const { mock, log, geo } = await openLog(10);
    mock.emitLine('line 11');
    const box = screen.getByRole('checkbox', { name: 'Автопрокрутка' });
    await userEvent.click(box);
    userScrollsTo(log, 0);
    expect(box).not.toBeChecked();
    mock.emitLine('line 12');
    expect(log.scrollTop).toBe(0);

    await userEvent.click(box);
    expect(box).toBeChecked();
    expect(log.scrollTop).toBe(geo.maxScroll);
  });
});

describe('log snapshot vs live lines', () => {
  it('a line pushed while the snapshot is loading is shown once, later lines are appended in order', async () => {
    const mock = installGpMock();
    let resolveSnapshot: (lines: string[]) => void = () => undefined;
    mock.gp.logs.get.mockImplementation(() => new Promise<string[]>((r) => (resolveSnapshot = r)));
    render(<App />);
    await userEvent.click(await screen.findByRole('button', { name: 'Журнал' }));

    mock.emitLine('10:00:02 INFO [vpn] B'); // already part of the snapshot below
    mock.emitLine('10:00:03 INFO [vpn] C'); // arrived after main took the snapshot
    resolveSnapshot(['10:00:01 INFO [vpn] A', '10:00:02 INFO [vpn] B']);
    await screen.findByText('10:00:03 INFO [vpn] C');
    mock.emitLine('10:00:04 INFO [vpn] D');

    const log = screen.getByRole('log', { name: 'Журнал событий' });
    expect([...log.children].map((c) => c.textContent)).toEqual([
      '10:00:01 INFO [vpn] A',
      '10:00:02 INFO [vpn] B',
      '10:00:03 INFO [vpn] C',
      '10:00:04 INFO [vpn] D',
    ]);
  });

  it('shows an empty state when the log cannot be read, and still shows live lines', async () => {
    const mock = installGpMock();
    mock.gp.logs.get.mockRejectedValue(new Error('boom'));
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    render(<App />);
    await userEvent.click(await screen.findByRole('button', { name: 'Журнал' }));
    expect(await screen.findByText('Журнал пуст.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Копировать' })).toBeDisabled();
    mock.emitLine('live');
    expect(screen.getByText('live')).toBeInTheDocument();
    expect(consoleError).toHaveBeenCalled();
    consoleError.mockRestore();
  });
});
