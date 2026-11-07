/** Map API error details to copy. Generic 401s stay generic on purpose. */
export function authErrorMessage(err: unknown): string {
  if (err && typeof err === "object" && "status" in err) {
    const { status, detail } = err as { status: number; detail: unknown };
    if (status === 401) return "Email or password is incorrect, or the email is not verified yet.";
    if (status === 429) return "Too many attempts. Please wait a few minutes and try again.";
    if (status === 422) return "Please check the highlighted fields.";
    if (detail === "registration_failed")
      return "That email can't be registered. Try signing in instead.";
    if (detail === "invalid_or_expired_token") return "This link has expired or was already used.";
    if (typeof detail === "string") return detail.replaceAll("_", " ");
  }
  return "Something went wrong. Please try again.";
}
