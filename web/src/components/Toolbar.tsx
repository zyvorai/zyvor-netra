// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import type { ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';

// Browse-tier primitives (docs/design/APPLE-UX-CONTRACT.md). Styling lives in
// styles/apple-story.css; these are thin wrappers so pages share one shape.

type ToolbarProps = {
  search?: string;
  onSearchChange?: (value: string) => void;
  placeholder?: string;
  searchLabel?: string;
  trailing?: ReactNode;
};

export function Toolbar({ search, onSearchChange, placeholder = 'Search', searchLabel, trailing }: ToolbarProps) {
  return (
    <div className="toolbar-pill" role="search">
      {onSearchChange && (
        <input
          className="input-field"
          type="search"
          value={search ?? ''}
          placeholder={placeholder}
          aria-label={searchLabel ?? placeholder}
          onChange={(e) => onSearchChange(e.target.value)}
        />
      )}
      {trailing && <div className="toolbar-pill__trailing">{trailing}</div>}
    </div>
  );
}

export function TableWrap({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={className ? `table-wrap ${className}` : 'table-wrap'}>{children}</div>;
}

type ListEmptyProps = { title: string; description?: string; action?: ReactNode; icon?: LucideIcon; compact?: boolean };

export function ListEmpty({ title, description, action, icon: Icon, compact }: ListEmptyProps) {
  return (
    <div className={compact ? 'list-empty list-empty--compact' : 'list-empty'}>
      {Icon && (
        <span className="list-empty__icon" aria-hidden="true">
          <Icon size={20} strokeWidth={1.75} />
        </span>
      )}
      <h3>{title}</h3>
      {description && <p>{description}</p>}
      {action}
    </div>
  );
}
