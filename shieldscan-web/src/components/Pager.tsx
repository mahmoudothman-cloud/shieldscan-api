import { Button } from "./ui";

export function Pager({
  page,
  total,
  count,
  onPage,
}: {
  page: number;
  total: number;
  count: number;
  onPage: (p: number) => void;
}) {
  if (total <= 1) return <p className="mt-3 text-xs text-ink-3">{count} total</p>;
  return (
    <div className="mt-3 flex items-center justify-between text-xs text-ink-3">
      <span>
        {count} total · page {page} of {total}
      </span>
      <div className="flex gap-2">
        <Button size="sm" variant="secondary" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          Previous
        </Button>
        <Button
          size="sm"
          variant="secondary"
          disabled={page >= total}
          onClick={() => onPage(page + 1)}
        >
          Next
        </Button>
      </div>
    </div>
  );
}
