export function canonicalJSON(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function sanitizeOpenClawResult(result, model) {
  if (!result || typeof result !== "object" || !Array.isArray(result.payloads) || result.payloads.length > 8) {
    throw new Error("OpenClaw returned an invalid result");
  }
  const payloads = result.payloads.map((payload) => {
    if (!payload || typeof payload !== "object" || typeof payload.text !== "string" ||
        Buffer.byteLength(payload.text) > (64 << 10) || (payload.mediaUrl !== null && payload.mediaUrl !== undefined)) {
      throw new Error("OpenClaw returned an unsupported payload");
    }
    return { text: payload.text, media_url: null };
  });
  const agentMeta = result.meta?.agentMeta;
  const toolSummary = result.meta?.toolSummary;
  if (!agentMeta || agentMeta.provider !== "steward" || agentMeta.model !== model ||
      !Number.isSafeInteger(result.meta?.durationMs) || result.meta.durationMs < 0 ||
      !toolSummary || !Number.isSafeInteger(toolSummary.calls) || toolSummary.calls < 0 || toolSummary.calls > 64 ||
      !Number.isSafeInteger(toolSummary.failures) || toolSummary.failures < 0 || toolSummary.failures > toolSummary.calls ||
      !Array.isArray(toolSummary.tools) || toolSummary.tools.length > 2 ||
      toolSummary.tools.some((tool) => tool !== "read" && tool !== "exec")) {
    throw new Error("OpenClaw result authority metadata is invalid");
  }
  return {
    payloads,
    meta: {
      duration_ms: result.meta.durationMs,
      model,
      provider: "steward",
      tool_calls: toolSummary.calls,
      tool_failures: toolSummary.failures,
      tools: [...toolSummary.tools],
    },
  };
}
