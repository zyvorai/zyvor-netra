import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';

type RevealProps = {
  children: ReactNode;
  className?: string;
  /** Stagger delay in ms, for revealing a sequence of siblings. */
  delay?: number;
};

/**
 * Fades/slides a section in once it scrolls into view. Falls back to
 * always-visible (no animation) when IntersectionObserver isn't available
 * or the user prefers reduced motion — handled in CSS via `.zv-reveal`
 * (see styles.css). Ported from website/src/components/Reveal.
 */
export default function Reveal({ children, className, delay = 0 }: RevealProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const node = ref.current;
    if (!node || typeof IntersectionObserver === 'undefined') {
      setVisible(true);
      return;
    }
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setVisible(true);
          observer.disconnect();
        }
      },
      { threshold: 0.15 }
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  const cls = ['zv-reveal', visible && 'zv-reveal--visible', className].filter(Boolean).join(' ');

  return (
    <div ref={ref} className={cls} style={delay ? { transitionDelay: `${delay}ms` } : undefined}>
      {children}
    </div>
  );
}
