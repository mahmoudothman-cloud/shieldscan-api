/**
 * Minimal Markdown renderer for AI-written fixes and summaries.
 *
 * Covers what the pipeline emits (fix_generation.py / summary.py):
 * `##` headings, fenced code blocks, bullet and numbered lists,
 * paragraphs, and inline `code` / **bold**. Output is React elements,
 * never HTML strings, so model output cannot inject markup. Anything
 * fancier than this list falls back to a plain paragraph.
 */

import { parseMarkdown, renderInline } from "@/lib/markdown";

export function Markdown({ source, className }: { source: string; className?: string }) {
  const blocks = parseMarkdown(source);
  return (
    <div className={className}>
      {blocks.map((b, idx) => {
        switch (b.kind) {
          case "h":
            return b.level <= 2 ? (
              <h3
                key={idx}
                className="mt-5 mb-2 text-sm font-semibold uppercase tracking-wide text-ink-3 first:mt-0"
              >
                {b.text}
              </h3>
            ) : (
              <h4 key={idx} className="mt-4 mb-1 text-sm font-semibold text-ink">
                {b.text}
              </h4>
            );
          case "code":
            return (
              <pre
                key={idx}
                className="my-2 overflow-x-auto rounded-control bg-ink p-3 text-xs leading-5 text-[#e6edf3]"
                data-lang={b.lang}
              >
                <code>{b.text}</code>
              </pre>
            );
          case "ul":
            return (
              <ul key={idx} className="my-2 list-disc space-y-1 pl-5 text-sm text-ink">
                {b.items.map((it, j) => (
                  <li key={j}>{renderInline(it)}</li>
                ))}
              </ul>
            );
          case "ol":
            return (
              <ol key={idx} className="my-2 list-decimal space-y-1 pl-5 text-sm text-ink">
                {b.items.map((it, j) => (
                  <li key={j}>{renderInline(it)}</li>
                ))}
              </ol>
            );
          default:
            return (
              <p key={idx} className="my-2 text-sm leading-6 text-ink">
                {renderInline(b.text)}
              </p>
            );
        }
      })}
    </div>
  );
}
