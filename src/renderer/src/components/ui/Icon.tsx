/** Inline SVG icons (Fluent-like 20px outlines). Decorative: hidden from assistive tech. */
import type { SVGProps } from 'react';

type IconProps = Omit<SVGProps<SVGSVGElement>, 'children'> & { size?: number };

function make(paths: React.JSX.Element) {
  return function Icon({ size = 20, ...rest }: IconProps): React.JSX.Element {
    return (
      <svg
        width={size}
        height={size}
        viewBox="0 0 20 20"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
        focusable="false"
        {...rest}
      >
        {paths}
      </svg>
    );
  };
}

export const PowerIcon = make(
  <>
    <path d="M10 2.75v7" />
    <path d="M6.1 4.9a6.25 6.25 0 1 0 7.8 0" />
  </>,
);
export const ShieldIcon = make(
  <path d="M10 2.5 4 4.75v4.6c0 3.7 2.5 6.6 6 8.15 3.5-1.55 6-4.45 6-8.15v-4.6L10 2.5Z" />,
);
export const ProfilesIcon = make(
  <>
    <circle cx="10" cy="10" r="7.25" />
    <path d="M2.75 10h14.5M10 2.75c2 2 2.9 4.4 2.9 7.25S12 15.25 10 17.25M10 2.75C8 4.75 7.1 7.15 7.1 10S8 15.25 10 17.25" />
  </>,
);
export const LogIcon = make(
  <>
    <path d="M5.75 2.75h6l3.5 3.5v10.5a.5.5 0 0 1-.5.5h-9a.5.5 0 0 1-.5-.5V3.25a.5.5 0 0 1 .5-.5Z" />
    <path d="M11.75 2.75v3.5h3.5M7.5 10h5M7.5 13h5" />
  </>,
);
export const SettingsIcon = make(
  <>
    <circle cx="10" cy="10" r="2.5" />
    <path d="M8.6 2.9h2.8l.45 2 1.3.75 1.95-.6 1.4 2.4-1.5 1.4v1.5l1.5 1.4-1.4 2.4-1.95-.6-1.3.75-.45 2H8.6l-.45-2-1.3-.75-1.95.6-1.4-2.4 1.5-1.4v-1.5l-1.5-1.4 1.4-2.4 1.95.6 1.3-.75.45-2Z" />
  </>,
);
export const PlusIcon = make(<path d="M10 4v12M4 10h12" />);
export const EditIcon = make(<path d="m12.5 4 3.5 3.5-8.5 8.5H4v-3.5L12.5 4Z" />);
export const DeleteIcon = make(
  <>
    <path d="M3.5 5.5h13M8 5.5V3.75h4V5.5M5.25 5.5l.75 11h8l.75-11" />
  </>,
);
export const CopyIcon = make(
  <>
    <rect x="6.75" y="6.75" width="9.5" height="9.5" rx="1.5" />
    <path d="M13.25 6.75v-2a1 1 0 0 0-1-1h-7.5a1 1 0 0 0-1 1v7.5a1 1 0 0 0 1 1h2" />
  </>,
);
export const FolderIcon = make(
  <path d="M2.75 5.25a1 1 0 0 1 1-1h3.6l1.6 1.75h7.3a1 1 0 0 1 1 1v8.25a1 1 0 0 1-1 1H3.75a1 1 0 0 1-1-1v-10Z" />,
);
export const CloseIcon = make(<path d="m5 5 10 10M15 5 5 15" />);
export const BackIcon = make(<path d="M16 10H4.5M9 5l-5 5 5 5" />);
export const ErrorIcon = make(
  <>
    <circle cx="10" cy="10" r="7.25" />
    <path d="M10 6v4.5M10 13.6v.15" />
  </>,
);
export const WarningIcon = make(
  <>
    <path d="M8.7 3.3a1.5 1.5 0 0 1 2.6 0l6 10.5A1.5 1.5 0 0 1 16 16H4a1.5 1.5 0 0 1-1.3-2.2l6-10.5Z" />
    <path d="M10 7.5v3.5M10 13.4v.1" />
  </>,
);
export const InfoIcon = make(
  <>
    <circle cx="10" cy="10" r="7.25" />
    <path d="M10 9v4.75M10 6.4v.1" />
  </>,
);
export const CheckIcon = make(<path d="m4.5 10.5 3.5 3.5 7.5-8" />);
export const ChevronIcon = make(<path d="m7.5 4.5 5.5 5.5-5.5 5.5" />);
