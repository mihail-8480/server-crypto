export function normalizeBase64(str: string) {
  const base64Encoded = str.replace(/-/g, "+").replace(/_/g, "/");
  const padding = str.length % 4 === 0 ? "" : "=".repeat(4 - (str.length % 4));
  return base64Encoded + padding;
}

export function toBase64URL(base64: string) {
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
