// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import type { ReactNode } from 'react';
import Reveal from '../Reveal';
import { ToneDot, type Tone } from './tone';

type SectionProps = {
  eyebrow?: string;
  title?: string;
  tone?: Tone;
  lede?: ReactNode;
  /** Long explainer text, folded under "How this is measured". */
  about?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  /** Grid span: 3 (full width, default), 2 or 1. */
  span?: 1 | 2 | 3;
  className?: string;
  reveal?: boolean;
};

export default function Section({ eyebrow, title, tone, lede, about, actions, children, span = 3, className, reveal = true }: SectionProps) {
  const body = (
    <section className={['card', 'kit-section', className].filter(Boolean).join(' ')}>
      {(eyebrow || title || actions) && (
        <header className="kit-section__head">
          <div>
            {eyebrow && (
              <p className="kit-eyebrow">
                {tone && <ToneDot tone={tone} />}
                {eyebrow}
              </p>
            )}
            {title && <h2 className="card-title">{title}</h2>}
          </div>
          {actions && <div className="kit-section__actions">{actions}</div>}
        </header>
      )}
      {lede && <p className="kit-lede">{lede}</p>}
      {children}
      {about && (
        <details className="kit-about">
          <summary>How this is measured</summary>
          <div>{about}</div>
        </details>
      )}
    </section>
  );
  const spanClass = span === 3 ? 'span3' : span === 2 ? 'span2' : undefined;
  if (!reveal) return spanClass ? <div className={spanClass}>{body}</div> : body;
  return <Reveal className={spanClass}>{body}</Reveal>;
}
