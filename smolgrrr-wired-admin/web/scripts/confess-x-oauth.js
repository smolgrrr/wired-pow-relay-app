import crypto from "node:crypto";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = process.env.WIRED_DATA_DIR || path.join(__dirname, "..", "data");
const tokenStoreFile =
  process.env.CONFESS_X_TOKEN_STORE_FILE || path.join(dataDir, "confess-x-tokens.json");
const clientId = String(process.env.CONFESS_X_CLIENT_ID || process.env.X_CLIENT_ID || "").trim();
const clientSecret = String(
  process.env.CONFESS_X_CLIENT_SECRET || process.env.X_CLIENT_SECRET || "",
).trim();
const redirectUri = String(
  process.env.CONFESS_X_REDIRECT_URI || process.env.REDIRECT_URI || "http://localhost:8080/callback",
).trim();
const scopes = String(
  process.env.CONFESS_X_SCOPES || "tweet.read users.read tweet.write offline.access",
)
  .split(/\s+/)
  .map((scope) => scope.trim())
  .filter(Boolean);

function usage() {
  console.error(`Usage:
  CONFESS_X_CLIENT_ID=... CONFESS_X_CLIENT_SECRET=... npm run confess:x:oauth

Optional env:
  CONFESS_X_REDIRECT_URI      default: http://localhost:8080/callback
  CONFESS_X_TOKEN_STORE_FILE  default: ./data/confess-x-tokens.json
  CONFESS_X_SCOPES           default: tweet.read users.read tweet.write offline.access
`);
}

function base64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

async function sha256Base64Url(value) {
  return base64Url(crypto.createHash("sha256").update(value).digest());
}

function authorizationUrl({ state, codeChallenge }) {
  const url = new URL("https://x.com/i/oauth2/authorize");
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("scope", scopes.join(" "));
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

function extractCallbackCode(value, expectedState) {
  const trimmed = String(value || "").trim();
  if (!trimmed) throw new Error("empty callback URL/code");

  if (!trimmed.includes("://") && !trimmed.includes("?")) {
    return trimmed;
  }

  const url = new URL(trimmed);
  const error = url.searchParams.get("error");
  if (error) {
    const description = url.searchParams.get("error_description");
    throw new Error(description ? `${error}: ${description}` : error);
  }

  const state = url.searchParams.get("state");
  if (state && state !== expectedState) {
    throw new Error("callback state did not match this OAuth attempt");
  }

  const code = url.searchParams.get("code");
  if (!code) throw new Error("callback URL did not include a code parameter");
  return code;
}

async function exchangeCode({ code, codeVerifier }) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier,
  });
  const headers = {
    "Content-Type": "application/x-www-form-urlencoded",
  };

  if (clientSecret) {
    headers.Authorization = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString(
      "base64",
    )}`;
  } else {
    body.set("client_id", clientId);
  }

  const response = await fetch("https://api.x.com/2/oauth2/token", {
    method: "POST",
    headers,
    body,
  });
  const text = await response.text();
  const payload = text ? JSON.parse(text) : {};

  if (!response.ok) {
    throw new Error(`token exchange failed (${response.status}): ${JSON.stringify(payload)}`);
  }
  if (!payload.access_token || !payload.refresh_token) {
    throw new Error("token exchange did not return both access_token and refresh_token");
  }

  return payload;
}

async function writeTokenStore(token) {
  const now = Date.now();
  const data = {
    version: 1,
    accessToken: token.access_token,
    refreshToken: token.refresh_token,
    tokenType: token.token_type || "bearer",
    scope: token.scope || scopes.join(" "),
    expiresAt: now + Math.max(60, Number(token.expires_in || 7200) - 60) * 1000,
    updatedAt: now,
  };

  await mkdir(path.dirname(tokenStoreFile), { recursive: true });
  await writeFile(tokenStoreFile, `${JSON.stringify(data, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  await chmod(tokenStoreFile, 0o600);
}

async function main() {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    usage();
    return;
  }

  if (!clientId) {
    usage();
    throw new Error("CONFESS_X_CLIENT_ID or X_CLIENT_ID is required");
  }

  const state = base64Url(crypto.randomBytes(32));
  const codeVerifier = base64Url(crypto.randomBytes(32));
  const codeChallenge = await sha256Base64Url(codeVerifier);
  const url = authorizationUrl({ state, codeChallenge });

  console.log("Open this URL with the dedicated X account:");
  console.log(url);
  console.log("");
  console.log("After X redirects to localhost, paste the full callback URL here.");
  console.log("The browser page may fail to load; copy the URL from the address bar.");

  const rl = createInterface({ input, output });
  try {
    const callback = await rl.question("Callback URL or code: ");
    const code = extractCallbackCode(callback, state);
    const token = await exchangeCode({ code, codeVerifier });
    await writeTokenStore(token);
  } finally {
    rl.close();
  }

  console.log(`Saved X token store: ${tokenStoreFile}`);
  console.log("Set CONFESS_X_ENABLED=true and CONFESS_X_DRY_RUN=false when ready to post.");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
