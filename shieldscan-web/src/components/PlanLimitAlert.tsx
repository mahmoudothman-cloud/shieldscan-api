import { Link } from "react-router";

import { Alert } from "@/components/ui";
import { planLimitMessage, type PlanLimitDetail } from "@/lib/plan";

/** The one way a plan cap is shown: what hit the limit, and where to upgrade. */
export function PlanLimitAlert({ limit }: { limit: PlanLimitDetail }) {
  return (
    <Alert tone="info">
      {planLimitMessage(limit)}{" "}
      <Link to="/settings/billing" className="font-medium underline">
        See plans
      </Link>
    </Alert>
  );
}
