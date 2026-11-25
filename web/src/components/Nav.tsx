import { useEffect, useRef, useState } from 'react';
import DigestChip from './DigestChip';
import ThemeMenu from './ThemeMenu';

import { navGroups, type Page } from '../lib/navGroups';

export type { Page };

const OPEN_DELAY_MS = 120;
const CLOSE_DELAY_MS = 450;

export default function Nav({
  page,
  setPage,
  onLogout,
}: {
  page: Page;
  setPage: (p: Page) => void;
  onLogout: () => void;
}) {
  const [openGroup, setOpenGroup] = useState<string | null>(null);
  const openTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const closeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const navRef = useRef<HTMLElement | null>(null);
  const triggerRefs = useRef<Record<string, HTMLButtonElement | null>>({});

  const clearTimers = () => {
    if (openTimer.current) clearTimeout(openTimer.current);
    if (closeTimer.current) clearTimeout(closeTimer.current);
    openTimer.current = null;
    closeTimer.current = null;
  };

  const scheduleOpen = (label: string) => {
    clearTimers();
    openTimer.current = setTimeout(() => setOpenGroup(label), OPEN_DELAY_MS);
  };

  const scheduleClose = () => {
    clearTimers();
    closeTimer.current = setTimeout(() => setOpenGroup(null), CLOSE_DELAY_MS);
  };

  const toggleGroup = (label: string) => {
    clearTimers();
    setOpenGroup((cur) => (cur === label ? null : label));
  };

  useEffect(() => () => clearTimers(), []);

  useEffect(() => {
    if (!openGroup) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      const label = openGroup;
      setOpenGroup(null);
      triggerRefs.current[label]?.focus();
    };
    const onPointerDown = (e: MouseEvent) => {
      if (navRef.current && !navRef.current.contains(e.target as Node)) setOpenGroup(null);
    };
    document.addEventListener('keydown', onKeyDown);
    document.addEventListener('mousedown', onPointerDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.removeEventListener('mousedown', onPointerDown);
    };
  }, [openGroup]);

  return (
    <nav className="nav" aria-label="Global" ref={navRef}>
      <div className="nav-inner">
        <button type="button" className="brand" onClick={() => setPage('overview')} aria-label="Netra home">
          <img src="/zyvor-logomark.svg" alt="" className="brand-mark" aria-hidden />
          Netra
        </button>
        <div className="navlinks">
          {navGroups.map((g) =>
            g.children ? (
              <div
                key={g.label}
                className="navgroup"
                onMouseEnter={() => scheduleOpen(g.label)}
                onMouseLeave={scheduleClose}
              >
                <button
                  type="button"
                  ref={(el) => {
                    triggerRefs.current[g.label] = el;
                  }}
                  className={g.children.some((c) => c.page === page) ? 'active' : ''}
                  aria-haspopup="true"
                  aria-expanded={openGroup === g.label}
                  onClick={() => toggleGroup(g.label)}
                >
                  {g.label}
                </button>
                <div
                  className={`mega-panel${openGroup === g.label ? ' open' : ''}`}
                  role="region"
                  aria-label={g.label}
                  onMouseEnter={() => scheduleOpen(g.label)}
                  onMouseLeave={scheduleClose}
                >
                  <div className="mega-grid">
                    {g.children.map((c) => (
                      <button
                        key={c.page}
                        type="button"
                        className={page === c.page ? 'active' : ''}
                        aria-current={page === c.page ? 'page' : undefined}
                        onClick={() => {
                          setPage(c.page);
                          setOpenGroup(null);
                        }}
                      >
                        <span className="mega-link-label">{c.label}</span>
                        <span className="mega-link-blurb">{c.blurb}</span>
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <button
                key={g.page}
                type="button"
                className={page === g.page ? 'active' : ''}
                aria-current={page === g.page ? 'page' : undefined}
                onClick={() => setPage(g.page as Page)}
              >
                {g.label}
              </button>
            )
          )}
        </div>
        <div className="nav-actions">
          <DigestChip onOpen={() => setPage('ai')} />
          <button type="button" className="theme-toggle" onClick={onLogout} aria-label="Log out" title="Log out">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
              <path d="M15 4H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8" strokeLinecap="round" strokeLinejoin="round" />
              <path d="M10 12h11m0 0-3.5-3.5M21 12l-3.5 3.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </button>
          <ThemeMenu />
        </div>
      </div>
    </nav>
  );
}
