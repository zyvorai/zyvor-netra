// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
import { useEffect, useRef, useState, type KeyboardEvent } from 'react';
import { Check, Monitor, Moon, Sun } from 'lucide-react';
import { applyPreference, followSystemTheme, readStoredPreference, type ThemePreference } from '../theme';
import { usePaintedTheme } from '../hooks/usePaintedTheme';

const OPTIONS = [
  { value: 'light', label: 'Light', Icon: Sun },
  { value: 'dark', label: 'Dark', Icon: Moon },
  { value: 'system', label: 'System', Icon: Monitor },
] as const;

/** Appearance menu: Light, Dark, or follow the operating system. */
export default function ThemeMenu() {
  const [preference, setPreference] = useState<ThemePreference>(readStoredPreference);
  const painted = usePaintedTheme();
  const [open, setOpen] = useState(false);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const current = OPTIONS.find((o) => o.value === preference) ?? OPTIONS[2];
  const ButtonIcon = painted === 'dark' ? Moon : Sun;

  useEffect(() => followSystemTheme(preference), [preference]);

  useEffect(() => {
    if (!open) return;
    menuRef.current?.querySelector<HTMLElement>('[aria-checked="true"]')?.focus();
    const onPointerDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [open]);

  const close = () => {
    setOpen(false);
    buttonRef.current?.focus();
  };

  const choose = (next: ThemePreference) => {
    applyPreference(next);
    setPreference(next);
    close();
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'Escape' || event.key === 'Tab') {
      event.stopPropagation();
      if (event.key === 'Escape') event.preventDefault();
      close();
      return;
    }
    const items = Array.from(menuRef.current?.querySelectorAll<HTMLElement>('[role="menuitemradio"]') ?? []);
    const index = items.indexOf(document.activeElement as HTMLElement);
    const next =
      event.key === 'ArrowDown' ? (index + 1) % items.length
      : event.key === 'ArrowUp' ? (index - 1 + items.length) % items.length
      : event.key === 'Home' ? 0
      : event.key === 'End' ? items.length - 1
      : -1;
    if (next < 0) return;
    event.preventDefault();
    items[next]?.focus();
  };

  return (
    <div className="theme-menu" ref={rootRef}>
      <button
        ref={buttonRef}
        type="button"
        className="theme-toggle"
        data-testid="theme-toggle"
        aria-label={`Appearance: ${current.label}`}
        title={`Appearance: ${current.label}`}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        <ButtonIcon size={17} strokeWidth={1.75} aria-hidden />
      </button>
      {open && (
        <div ref={menuRef} className="theme-menu__panel" role="menu" aria-label="Appearance" onKeyDown={onKeyDown}>
          {OPTIONS.map(({ value, label, Icon }) => (
            <button key={value} type="button" role="menuitemradio" aria-checked={preference === value} tabIndex={-1} onClick={() => choose(value)}>
              <Icon size={15} aria-hidden />
              <span>{label}</span>
              {preference === value && <Check size={15} aria-hidden />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
