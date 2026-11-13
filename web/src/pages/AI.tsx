// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import AskNetra from '../components/AskNetra';
import DigestChip from '../components/DigestChip';

/** First-class AI workspace — same AskNetra agent as Overview, with digest chip. */
export default function AI() {
  return (
    <div className="grid">
      <section className="card span3">
        <p className="eyebrow">ON-CALL</p>
        <h2 className="card-title">Digest and ask</h2>
        <p>Read-only briefs, drafts and the in-process agent graph. Never applies mode, rules or policy.</p>
        <div style={{ marginTop: '0.75rem' }}>
          <DigestChip />
        </div>
      </section>
      <div className="span3">
        <AskNetra />
      </div>
    </div>
  );
}
