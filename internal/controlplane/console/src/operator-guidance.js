const safeIdentity = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;

export function attentionCommand(item) {
  const identity = [
    item?.node_id,
    item?.command_id,
    item?.capacity_resource,
    item?.quota_resource,
  ].find((value) => typeof value === "string" && safeIdentity.test(value));
  if (!identity) {
    return "stewardctl explain";
  }
  return "stewardctl explain " + identity;
}

export function attentionGuidance(item) {
  const fallback = String(item?.reason || "operator_attention").replaceAll("_", " ");
  return {
    title: typeof item?.title === "string" && item.title ? item.title : fallback,
    explanation: typeof item?.explanation === "string" && item.explanation
      ? item.explanation
      : "Steward derived this finding from retained operational metadata.",
    impact: typeof item?.impact === "string" && item.impact
      ? item.impact
      : "Review the affected resource before granting more authority.",
    nextStep: typeof item?.next_step === "string" && item.next_step
      ? item.next_step
      : "Use stewardctl explain for the current safe next step.",
  };
}
