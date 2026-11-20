// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

export type HeroTint = 'green' | 'amber' | 'purple' | 'red' | 'cyan';

type PageHeroProps = {
  eyebrow: string;
  title: string;
  lede: string;
  tint?: HeroTint;
};

export default function PageHero({ eyebrow, title, lede, tint }: PageHeroProps) {
  return (
    <header className={tint ? `page-hero hero-tint-${tint}` : 'page-hero'}>
      <p className="eyebrow">{eyebrow}</p>
      <h1>{title}</h1>
      <p>{lede}</p>
    </header>
  );
}
