// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import type { ReactNode } from 'react';
import { compact } from './format';
import type { Tone } from './tone';

export type RankedItem = {
  name: string;
  count: number;
  detail?: ReactNode;
  tone?: Tone;
  action?: ReactNode;
  key?: string;
};

type RankedListProps = {
  items: RankedItem[];
  title?: string;
  empty?: ReactNode;
  limit?: number;
  format?: (n: number) => string;
  mono?: boolean;
};

export default function RankedList({ items, title, empty = 'Nothing observed yet.', limit = 10, format = compact, mono = true }: RankedListProps) {
  const top = items.slice(0, limit);
  const max = Math.max(1, ...top.map((x) => x.count || 0));
  return (
    <div className="kit-ranked">
      {title && <h3>{title}</h3>}
      {!top.length && (typeof empty === 'string' ? <p className="kit-ranked__empty">{empty}</p> : empty)}
      {top.length > 0 && (
        <ol>
          {top.map((x, i) => (
            <li key={x.key ?? x.name + i} className={x.tone ? `tone-${x.tone}` : undefined}>
              <div className="kit-ranked__row">
                <span className="kit-ranked__bar" style={{ width: `${Math.max(2, ((x.count || 0) / max) * 100)}%` }} aria-hidden="true" />
                <span className={mono ? 'kit-ranked__name mono' : 'kit-ranked__name'} title={x.name}>
                  {x.name}
                </span>
                <span className="kit-ranked__count">{format(x.count || 0)}</span>
              </div>
              {(x.detail || x.action) && (
                <div className="kit-ranked__meta">
                  {x.detail && <small>{x.detail}</small>}
                  {x.action}
                </div>
              )}
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
