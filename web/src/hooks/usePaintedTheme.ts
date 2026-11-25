// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
import { useEffect, useState } from 'react';
import { paintedTheme, type Theme } from '../theme';

/** The theme on screen, for canvases and WebGL that cannot read CSS variables live. */
export function usePaintedTheme(): Theme {
  const [theme, setTheme] = useState<Theme>(paintedTheme);
  useEffect(() => {
    const read = () => setTheme(paintedTheme());
    read();
    const observer = new MutationObserver(read);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    return () => observer.disconnect();
  }, []);
  return theme;
}
