import type { WebConfigEntry } from "./crypto";

function escapeXmlAttribute(value: string) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/'/g, "&apos;");
}

export function formatWebConfigEntries(entries: WebConfigEntry[]) {
  return entries
    .map(
      ({ key, value }) =>
        `<add key="${escapeXmlAttribute(key)}" value="${escapeXmlAttribute(value)}" />`,
    )
    .join("\n");
}
