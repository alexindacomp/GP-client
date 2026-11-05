import { render } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { TitleBar, titleBarMode } from './TitleBar';

describe('title bar', () => {
  it.each([
    ['win32', 'native'],
    ['darwin', 'overlay-mac'],
    ['linux', 'native'],
  ] as const)('%s → %s', (platform, mode) => {
    expect(titleBarMode(platform)).toBe(mode);
  });

  it('renders nothing for a native title bar', () => {
    const { container } = render(<TitleBar mode="native" />);
    expect(container).toBeEmptyDOMElement();
  });

  it('macOS overlay header is a Tauri drag region', () => {
    const { container } = render(<TitleBar mode="overlay-mac" />);
    expect(container.querySelector('header')).toHaveAttribute('data-tauri-drag-region');
  });
});
