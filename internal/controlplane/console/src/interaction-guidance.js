const interactionIDPattern = /^interaction-[a-f0-9]{64}$/u;
const tenantIDPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const controlCharacterPattern = /[\u0000-\u001f\u007f-\u009f]/u;

function shellQuote(value) {
  return "'" + String(value).replaceAll("'", "'\"'\"'") + "'";
}

function boundedResponse(value, maximum) {
  return typeof value === "string" && value.length > 0 && value.length <= maximum &&
    value.trim() === value && !controlCharacterPattern.test(value);
}

export function interactionResponseCommand(interaction, choice, text) {
  if (!interaction || !tenantIDPattern.test(interaction.tenant_id || "") ||
      !interactionIDPattern.test(interaction.interaction_id || "")) {
    throw new Error("The interaction identity is invalid.");
  }
  const options = Array.isArray(interaction.options) ? interaction.options : [];
  if (choice && (!boundedResponse(choice, 128) || !options.includes(choice))) {
    throw new Error("Choose one response offered by the agent.");
  }
  if (text && (!interaction.allow_text || !boundedResponse(text, 2048))) {
    throw new Error("The typed response is not allowed or exceeds its safe bound.");
  }
  if (!choice && !text) {
    throw new Error("Choose an option or enter a response.");
  }
  const parts = [
    "stewardctl", "control", "interaction", "respond",
    "-tenant-id", interaction.tenant_id,
    "-interaction-id", interaction.interaction_id,
  ];
  if (choice) {
    parts.push("-choice", choice);
  }
  if (text) {
    parts.push("-text", text);
  }
  parts.push("-key", "PATH_TO_TASK_PRIVATE_KEY", "-key-id", "TASK_KEY_ID");
  return parts.map(shellQuote).join(" ");
}
