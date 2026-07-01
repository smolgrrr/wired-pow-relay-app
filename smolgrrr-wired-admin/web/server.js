import crypto from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import {
  finalizeEvent,
  getEventHash,
  getPublicKey,
  nip19,
  Relay,
} from "nostr-tools";
import WebSocket, { WebSocketServer } from "ws";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const port = Number(process.env.PORT || 3000);
const backendUrl = process.env.RELAY_BACKEND_URL || "ws://relay:7777";
const minPow = Number(process.env.RELAY_MIN_POW || 16);
const dataDir = process.env.WIRED_DATA_DIR || path.join(__dirname, "data");
const snapshotCacheFile =
  process.env.FEED_SNAPSHOT_CACHE_FILE || path.join(dataDir, "feed-bootstrap.json");
const moderationStoreFile =
  process.env.WIRED_MODERATION_STORE || path.join(dataDir, "moderation.json");
const confessStoreFile =
  process.env.CONFESS_STORE_FILE || path.join(dataDir, "confess.json");
const refreshSeconds = Number(process.env.FEED_SNAPSHOT_REFRESH_SECONDS || 300);
const snapshotAgeHours = Number(process.env.FEED_SNAPSHOT_AGE_HOURS || 24);
const snapshotTimeoutMs = Number(process.env.FEED_SNAPSHOT_TIMEOUT_MS || 12_000);
const replyFetchDepth = Math.max(
  0,
  Math.min(Number(process.env.FEED_SNAPSHOT_REPLY_DEPTH || 2), 2),
);

const powRelays = envList("POW_RELAYS", ["wss://powrelay.xyz", "wss://pow.relays.land"]);
const enrichmentRelays = envList("ENRICHMENT_RELAYS", [
  "wss://relay.damus.io",
  "wss://offchain.pub",
  "wss://nos.lol",
  "wss://relay.primal.net",
  "wss://relay.nostr.band",
  "wss://nostr.wine",
  "wss://relay.snort.social",
]);
const threadRelays = [...new Set([...powRelays, ...enrichmentRelays])];
const confessRelays = envList("CONFESS_RELAYS", [backendUrl, ...threadRelays]);
const confessDailyLimit = Math.max(1, Number(process.env.CONFESS_DAILY_LIMIT || 6));
const confessBasePow = Math.max(minPow, Number(process.env.CONFESS_MIN_POW || minPow));
const confessMaxPow = Math.max(confessBasePow, Number(process.env.CONFESS_MAX_POW || 28));
const confessContentMaxLength = Math.max(
  1,
  Number(process.env.CONFESS_CONTENT_MAX_LENGTH || 2000),
);
const confessPublishTimeoutMs = Math.max(
  1000,
  Number(process.env.CONFESS_PUBLISH_TIMEOUT_MS || 8000),
);
const publicHostPatterns = envList("PUBLIC_HOSTS", []).map(normalizeHost).filter(Boolean);

const relayInfo = {
  name: process.env.RELAY_NAME || "Wired Admin",
  description:
    process.env.RELAY_DESCRIPTION ||
    "A Wired proof-of-work Nostr relay backed by strfry.",
  pubkey: process.env.RELAY_PUBKEY || undefined,
  contact: process.env.RELAY_CONTACT || undefined,
  icon: process.env.RELAY_ICON || undefined,
  supported_nips: [1, 9, 11, 13, 15, 20, 22, 33, 40],
  software:
    process.env.RELAY_SOFTWARE ||
    "https://github.com/smolgrrr/wired-admin",
  version: process.env.RELAY_VERSION || "0.2.4",
  limitation: {
    auth_required: false,
    payment_required: false,
    min_pow_difficulty: minPow,
  },
};

const securityHeaders = {
  "Content-Security-Policy":
    "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; connect-src 'self'; img-src 'self' https: data:; style-src 'self'; font-src 'self'",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy":
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()",
};

const stats = {
  startedAt: Date.now(),
  backendUrl,
  minPow,
  activeClients: 0,
  totalConnections: 0,
  clientMessages: 0,
  backendMessages: 0,
  publishAttempts: 0,
  acceptedPublishes: 0,
  powRejectedPublishes: 0,
  backendRejectedPublishes: 0,
  malformedMessages: 0,
  reqMessages: 0,
  closeMessages: 0,
  lastBackendOpenAt: null,
  lastBackendErrorAt: null,
  recent: [],
};

let snapshot = null;
let lastRefreshError = null;
let refreshPromise = null;
let confessLedgerQueue = Promise.resolve();

function envList(name, fallback) {
  const raw = process.env[name];
  if (!raw) return fallback;
  const values = raw
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  return values.length > 0 ? values : fallback;
}

function normalizeHost(value) {
  const trimmed = String(value || "").trim().toLowerCase();
  if (!trimmed) return "";

  try {
    return new URL(trimmed.includes("://") ? trimmed : `http://${trimmed}`).hostname
      .replace(/\.$/, "");
  } catch {
    return trimmed.split(":")[0].replace(/\.$/, "");
  }
}

function requestHost(req) {
  const forwardedHost = String(req.headers["x-forwarded-host"] || "")
    .split(",")[0]
    .trim();
  return normalizeHost(forwardedHost || req.headers.host || "");
}

function isPublicHost(req) {
  const host = requestHost(req);
  return Boolean(host && publicHostPatterns.some((pattern) => hostMatchesPattern(host, pattern)));
}

function hostMatchesPattern(host, pattern) {
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(1);
    return host.endsWith(suffix) && host.length > suffix.length;
  }

  return host === pattern;
}

function acceptsNostrJson(req) {
  return String(req.headers.accept || "").includes("application/nostr+json");
}

function isPublicHttpRouteAllowed(req) {
  const url = new URL(req.originalUrl || req.url || "/", "http://localhost");

  if (url.pathname === "/") {
    return req.method === "GET" && acceptsNostrJson(req);
  }

  if (url.pathname === "/api/feed/bootstrap") {
    return req.method === "GET" || req.method === "OPTIONS";
  }

  if (url.pathname === "/api/moderation/manifest") {
    return req.method === "GET" || req.method === "OPTIONS";
  }

  if (url.pathname === "/api/confess/status") {
    return req.method === "GET" || req.method === "OPTIONS";
  }

  if (url.pathname === "/api/confess") {
    return req.method === "POST" || req.method === "OPTIONS";
  }

  return false;
}

function addRecent(type, detail) {
  stats.recent.unshift({
    at: Date.now(),
    type,
    detail,
  });
  stats.recent = stats.recent.slice(0, 50);
}

function countLeadingZeroBits(hex) {
  let count = 0;
  for (const char of hex) {
    const nibble = Number.parseInt(char, 16);
    if (Number.isNaN(nibble)) return 0;
    if (nibble === 0) {
      count += 4;
      continue;
    }
    return count + Math.clz32(nibble) - 28;
  }
  return count;
}

function eventPow(event) {
  if (!event || typeof event !== "object" || typeof event.id !== "string") {
    return 0;
  }
  return countLeadingZeroBits(event.id);
}

function verifyPow(event, requiredPow = minPow) {
  if (!event || typeof event !== "object") {
    return { ok: false, reason: "invalid event", pow: 0 };
  }

  let hash;
  try {
    hash = getEventHash(event);
  } catch {
    return { ok: false, reason: "invalid event hash", pow: 0 };
  }

  if (hash !== event.id) {
    return {
      ok: false,
      reason: "event id does not match event hash",
      pow: countLeadingZeroBits(hash),
    };
  }

  const pow = countLeadingZeroBits(hash);
  const nonceTag = Array.isArray(event.tags)
    ? event.tags.find((tag) => Array.isArray(tag) && tag[0] === "nonce")
    : undefined;
  const claimedTarget = Number.parseInt(nonceTag?.[2] || "", 10);

  if (!nonceTag || Number.isNaN(claimedTarget)) {
    return { ok: false, reason: "missing nonce tag", pow };
  }

  if (claimedTarget < requiredPow) {
    return {
      ok: false,
      reason: `nonce target ${claimedTarget} is below ${requiredPow}`,
      pow,
    };
  }

  if (pow < requiredPow) {
    return { ok: false, reason: `proof ${pow} is below ${requiredPow}`, pow };
  }

  return { ok: true, reason: "", pow };
}

function safeJsonParse(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function sendOk(ws, eventId, ok, reason) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(["OK", eventId || "", ok, reason]));
  }
}

function summarizeEvent(event, pow) {
  return {
    id: event.id,
    kind: event.kind,
    pow,
    created_at: event.created_at,
  };
}

function setCorsHeaders(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Authorization, Content-Type, X-Admin-Token",
  );
}

function setSecurityHeaders(res) {
  for (const [header, value] of Object.entries(securityHeaders)) {
    res.setHeader(header, value);
  }
}

function isCronAuthorized(req) {
  const cronSecret = process.env.CRON_SECRET;
  if (!cronSecret) return true;
  return req.headers.authorization === `Bearer ${cronSecret}`;
}

function adminBearerToken(req) {
  const value = req.headers.authorization;
  if (!value?.startsWith("Bearer ")) return null;
  return value.slice("Bearer ".length).trim();
}

function isLocalRequest(req) {
  const remote = req.socket.remoteAddress || "";
  return remote === "127.0.0.1" || remote === "::1" || remote.startsWith("::ffff:127.");
}

function isAdminAuthorized(req) {
  if (isPublicHost(req)) return false;
  if (process.env.MODERATION_ADMIN_OPEN === "true") return true;

  const token = process.env.MODERATION_ADMIN_TOKEN;
  if (!token) return isLocalRequest(req) || process.env.NODE_ENV !== "production";
  return adminBearerToken(req) === token || req.headers["x-admin-token"] === token;
}

function normalizeUrl(value) {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "";
    return parsed.href;
  } catch {
    return "";
  }
}

function normalizeModerationValue(kind, value) {
  const trimmed = String(value || "").trim();
  if (!trimmed) return null;

  if (kind === "block_domain") {
    return (
      trimmed
        .replace(/^https?:\/\//i, "")
        .replace(/^www\./i, "")
        .split("/")[0]
        .trim()
        .toLowerCase() || null
    );
  }

  if (kind === "block_media_url") {
    return normalizeUrl(trimmed);
  }

  if (kind === "block_content_fingerprint") {
    return trimmed.startsWith("fnv1a:") ? trimmed : contentFingerprint(trimmed);
  }

  return trimmed.toLowerCase();
}

function uniqueSorted(values) {
  return [...new Set([...values].filter(Boolean))].sort();
}

const emptyModerationManifest = {
  updatedAt: 0,
  blockedEventIds: [],
  blockedThreadRoots: [],
  blockedMediaUrls: [],
  blockedDomains: [],
  blockedContentFingerprints: [],
};

async function readModerationStore() {
  try {
    const parsed = JSON.parse(await readFile(moderationStoreFile, "utf8"));
    if (parsed?.version === 1 && Array.isArray(parsed.actions)) return parsed;
  } catch {
    // Missing or malformed stores are treated as empty.
  }
  return { version: 1, actions: [] };
}

async function writeModerationStore(data) {
  await mkdir(path.dirname(moderationStoreFile), { recursive: true });
  const temp = `${moderationStoreFile}.${process.pid}.tmp`;
  await writeFile(temp, `${JSON.stringify(data, null, 2)}\n`, "utf8");
  await rename(temp, moderationStoreFile);
}

async function getModerationActions() {
  const store = await readModerationStore();
  return [...store.actions].sort((a, b) => b.createdAt - a.createdAt);
}

function manifestFromActions(actions) {
  if (actions.length === 0) return emptyModerationManifest;

  const blockedEventIds = new Set();
  const blockedThreadRoots = new Set();
  const blockedMediaUrls = new Set();
  const blockedDomains = new Set();
  const blockedContentFingerprints = new Set();

  for (const action of actions) {
    const normalized = normalizeModerationValue(action.kind, action.value);
    if (!normalized) continue;
    if (action.kind === "block_event") blockedEventIds.add(normalized);
    if (action.kind === "block_thread") {
      blockedEventIds.add(normalized);
      blockedThreadRoots.add(normalized);
    }
    if (action.kind === "block_media_url") blockedMediaUrls.add(normalized);
    if (action.kind === "block_domain") blockedDomains.add(normalized);
    if (action.kind === "block_content_fingerprint") {
      blockedContentFingerprints.add(normalized);
    }
  }

  return {
    updatedAt: actions.reduce((latest, action) => Math.max(latest, action.createdAt), 0),
    blockedEventIds: uniqueSorted(blockedEventIds),
    blockedThreadRoots: uniqueSorted(blockedThreadRoots),
    blockedMediaUrls: uniqueSorted(blockedMediaUrls),
    blockedDomains: uniqueSorted(blockedDomains),
    blockedContentFingerprints: uniqueSorted(blockedContentFingerprints),
  };
}

async function getModerationManifest() {
  return manifestFromActions((await readModerationStore()).actions);
}

async function createModerationAction(input) {
  const actionKinds = new Set([
    "block_event",
    "block_thread",
    "block_media_url",
    "block_domain",
    "block_content_fingerprint",
  ]);
  const reasons = new Set(["illegal", "spam", "abuse", "manual"]);

  if (!actionKinds.has(input.kind)) throw new Error("invalid action kind");
  if (!reasons.has(input.reason)) throw new Error("invalid reason");

  const normalizedValue = normalizeModerationValue(input.kind, input.value);
  if (!normalizedValue) throw new Error("invalid moderation value");

  const store = await readModerationStore();
  const action = {
    id: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`,
    kind: input.kind,
    value: normalizedValue,
    reason: input.reason,
    note: input.note?.trim() || undefined,
    createdAt: Date.now(),
    moderator: input.moderator?.trim() || "local-admin",
  };
  store.actions.push(action);
  await writeModerationStore(store);
  return action;
}

async function deleteModerationAction(id) {
  const store = await readModerationStore();
  const index = store.actions.findIndex((action) => action.id === id);
  if (index === -1) throw new Error("moderation action not found");

  const [action] = store.actions.splice(index, 1);
  await writeModerationStore(store);
  return action;
}

function utcDayKey(timeMs = Date.now()) {
  return new Date(timeMs).toISOString().slice(0, 10);
}

function nextUtcReset(day) {
  return new Date(Date.parse(`${day}T00:00:00.000Z`) + 24 * 60 * 60 * 1000);
}

async function readConfessStore() {
  try {
    const parsed = JSON.parse(await readFile(confessStoreFile, "utf8"));
    if (parsed?.version === 1 && Array.isArray(parsed.posts)) return parsed;
  } catch {
    // Missing or malformed stores are treated as empty.
  }
  return { version: 1, posts: [] };
}

async function writeConfessStore(data) {
  await mkdir(path.dirname(confessStoreFile), { recursive: true });
  const temp = `${confessStoreFile}.${process.pid}.tmp`;
  await writeFile(temp, `${JSON.stringify(data, null, 2)}\n`, "utf8");
  await rename(temp, confessStoreFile);
}

function todaysConfessPosts(store, now = Date.now()) {
  const day = utcDayKey(now);
  return store.posts
    .filter((post) => post.day === day)
    .sort((a, b) => a.createdAt - b.createdAt);
}

function adjustedConfessPow(posts, now = Date.now()) {
  if (posts.length >= confessDailyLimit) return confessMaxPow;
  if (posts.length === 0) return confessBasePow;

  const day = utcDayKey(now);
  const dayStartSeconds = Date.parse(`${day}T00:00:00.000Z`) / 1000;
  const nowSeconds = now / 1000;
  const targetSpacing = (24 * 60 * 60) / confessDailyLimit;
  const elapsed = Math.max(60, nowSeconds - dayStartSeconds);
  const expectedPosts = Math.max(0.25, elapsed / targetSpacing);
  const scheduleRatio = posts.length / expectedPosts;

  let intervalRatio = scheduleRatio;
  if (posts.length > 1) {
    const first = posts[0].createdAt / 1000;
    const last = posts[posts.length - 1].createdAt / 1000;
    const actualSpacing = Math.max(60, (last - first) / (posts.length - 1));
    intervalRatio = targetSpacing / actualSpacing;
  }

  const ratio = Math.max(scheduleRatio, intervalRatio);
  const adjustment = ratio > 1 ? Math.ceil(Math.log2(ratio)) : 0;
  const scarcityAdjustment = posts.length >= confessDailyLimit - 1 ? 1 : 0;
  return Math.min(confessMaxPow, confessBasePow + adjustment + scarcityAdjustment);
}

function confessStatusFromStore(store, now = Date.now()) {
  const day = utcDayKey(now);
  const posts = todaysConfessPosts(store, now);
  const count = posts.length;
  const remaining = Math.max(0, confessDailyLimit - count);
  const secretKey = parseConfessSecretKey();
  return {
    configured: Boolean(secretKey),
    pubkey: secretKey ? getPublicKey(secretKey) : "",
    day,
    count,
    limit: confessDailyLimit,
    remaining,
    minimumPow: adjustedConfessPow(posts, now),
    closed: remaining === 0,
    nextResetAt: nextUtcReset(day).toISOString(),
  };
}

function withConfessLedgerLock(task) {
  const run = confessLedgerQueue.then(task, task);
  confessLedgerQueue = run.catch(() => {});
  return run;
}

function hexToBytes(hex) {
  if (!/^[0-9a-f]{64}$/i.test(hex)) {
    throw new Error("expected 32-byte hex private key");
  }
  const bytes = new Uint8Array(32);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function parseConfessSecretKey() {
  const raw = String(process.env.CONFESS_NOSTR_SECRET_KEY || "").trim();
  if (!raw) return null;

  try {
    if (raw.startsWith("nsec1")) {
      const decoded = nip19.decode(raw);
      if (decoded.type !== "nsec" || !(decoded.data instanceof Uint8Array)) return null;
      return decoded.data;
    }
    return hexToBytes(raw);
  } catch {
    return null;
  }
}

const disallowedConfessContentPattern =
  /\b(?:(?:https?|wss?|ftp|ipfs):\/\/|(?:magnet|nostr):|www\.)[^\s<>"')\]]+|\b[a-z0-9.-]+\.(?:app|band|biz|blog|cloud|co|com|dev|fm|gg|info|io|is|land|link|lol|me|media|net|news|online|onion|org|site|social|to|tv|wine|xyz)(?:\/[^\s<>"')\]]*)?|\b[^\s<>"')\]]+\.(?:avif|gif|jpe?g|m4a|mov|mp3|mp4|ogg|png|svg|wav|webm|webp)(?:\?[^\s<>"')\]]*)?/i;

function hasDisallowedConfessContent(content) {
  return disallowedConfessContentPattern.test(String(content || ""));
}

function validateConfessAdmission(event, requiredPow, confessPubkey) {
  const result = verifyPow(event, requiredPow);
  if (!result.ok) return result;

  if (event.pubkey !== confessPubkey) {
    return { ok: false, reason: "confess proof pubkey does not match account", pow: result.pow };
  }

  if (event.kind !== 1) {
    return { ok: false, reason: "confess proof must be kind 1", pow: result.pow };
  }

  const content = String(event.content || "").trim();
  if (!content) {
    return { ok: false, reason: "empty confession", pow: result.pow };
  }

  if (hasDisallowedConfessContent(content)) {
    return { ok: false, reason: "links and media are not allowed", pow: result.pow };
  }

  if (content.length > confessContentMaxLength) {
    return {
      ok: false,
      reason: `confession exceeds ${confessContentMaxLength} characters`,
      pow: result.pow,
    };
  }

  return { ok: true, reason: "", pow: result.pow };
}

function buildConfessionEvent(admissionEvent, secretKey) {
  return finalizeEvent(
    {
      kind: admissionEvent.kind,
      content: admissionEvent.content.trim(),
      tags: admissionEvent.tags,
      created_at: admissionEvent.created_at,
      pubkey: admissionEvent.pubkey,
    },
    secretKey,
  );
}

function withTimeout(promise, timeoutMs, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out`)), timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

async function publishConfessionEvent(event) {
  const results = await Promise.allSettled(
    confessRelays.map(async (url) => {
      const relay = await withTimeout(Relay.connect(url), confessPublishTimeoutMs, url);
      try {
        await withTimeout(relay.publish(event), confessPublishTimeoutMs, url);
        return normalizeRelayUrl(relay.url || url);
      } finally {
        try {
          relay.close();
        } catch {
          // Relay already closed.
        }
      }
    }),
  );

  return uniqueSorted(
    results
      .filter((result) => result.status === "fulfilled")
      .map((result) => result.value),
  );
}

async function createConfession(admissionEvent) {
  const secretKey = parseConfessSecretKey();
  if (!secretKey) {
    const error = new Error("confess account is not configured");
    error.statusCode = 503;
    throw error;
  }

  return withConfessLedgerLock(async () => {
    const store = await readConfessStore();
    const status = confessStatusFromStore(store);

    if (status.closed) {
      const error = new Error("daily confess cap reached");
      error.statusCode = 429;
      throw error;
    }

    if (store.posts.some((post) => post.proofId === admissionEvent?.id)) {
      const error = new Error("confess proof has already been used");
      error.statusCode = 409;
      throw error;
    }

    const confessPubkey = getPublicKey(secretKey);
    const proof = validateConfessAdmission(admissionEvent, status.minimumPow, confessPubkey);
    if (!proof.ok) {
      const error = new Error(proof.reason);
      error.statusCode = 400;
      error.pow = proof.pow;
      throw error;
    }

    const event = buildConfessionEvent(admissionEvent, secretKey);
    const acceptedRelays = await publishConfessionEvent(event);
    if (acceptedRelays.length === 0) {
      const error = new Error("no relay accepted the confession");
      error.statusCode = 502;
      throw error;
    }

    store.posts.push({
      day: status.day,
      eventId: event.id,
      proofId: admissionEvent.id,
      pow: proof.pow,
      createdAt: Date.now(),
      acceptedRelays,
    });
    await writeConfessStore(store);

    const nextStatus = confessStatusFromStore(store);
    return {
      event,
      acceptedRelays,
      count: nextStatus.count,
      remaining: nextStatus.remaining,
      minimumPow: nextStatus.minimumPow,
      nextResetAt: nextStatus.nextResetAt,
    };
  });
}

const httpUrlPattern = /https?:\/\/[^\s<>"')\]]+/gi;
const mediaExtensionPattern =
  /\.(?:jpe?g|png|gif|webp|mp4|webm|mov|mp3|wav|ogg|m4a)(?:\?|$)/i;

function imetaUrls(event) {
  return (event.tags || [])
    .filter((tag) => tag[0] === "imeta")
    .flatMap((tag) =>
      tag
        .slice(1)
        .filter((part) => part.startsWith("url "))
        .map((part) => part.slice("url ".length).trim()),
    );
}

function eventUrls(event) {
  const contentUrls = [...String(event.content || "").matchAll(httpUrlPattern)].map(
    (match) => match[0],
  );
  return uniqueSorted([...contentUrls, ...imetaUrls(event)].map(normalizeUrl));
}

function domainFromUrl(value) {
  const normalized = normalizeUrl(value);
  if (!normalized) return null;
  try {
    return new URL(normalized).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return null;
  }
}

function mediaUrlsFromEvent(event) {
  return uniqueSorted(eventUrls(event).filter((url) => mediaExtensionPattern.test(url)));
}

function parsedRepostEvent(event) {
  if (event.kind !== 6) return null;
  try {
    const parsed = JSON.parse(event.content);
    if (
      typeof parsed.id !== "string" ||
      typeof parsed.pubkey !== "string" ||
      typeof parsed.content !== "string" ||
      !Array.isArray(parsed.tags) ||
      typeof parsed.created_at !== "number" ||
      typeof parsed.kind !== "number" ||
      typeof parsed.sig !== "string"
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function visibleEventVariants(event) {
  const repost = parsedRepostEvent(event);
  return repost ? [event, repost] : [event];
}

function rootReferences(event) {
  return (event.tags || []).filter((tag) => tag[0] === "e" && tag[1]).map((tag) => tag[1]);
}

function normalizeContentForFingerprint(content) {
  return String(content || "")
    .replace(httpUrlPattern, "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function contentFingerprint(content) {
  const normalized = normalizeContentForFingerprint(content);
  let hash = 0x811c9dc5;
  for (let index = 0; index < normalized.length; index += 1) {
    hash ^= normalized.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return `fnv1a:${(hash >>> 0).toString(16).padStart(8, "0")}`;
}

function isEventModerated(event, manifest) {
  const variants = visibleEventVariants(event);
  const blockedEventIds = new Set(manifest.blockedEventIds);
  if (variants.some((variant) => blockedEventIds.has(variant.id.toLowerCase()))) {
    return true;
  }

  const blockedThreadRoots = new Set(manifest.blockedThreadRoots);
  if (
    variants.some((variant) =>
      rootReferences(variant).some((id) => blockedThreadRoots.has(id.toLowerCase())),
    )
  ) {
    return true;
  }

  const blockedMediaUrls = new Set(manifest.blockedMediaUrls);
  if (
    variants.some((variant) =>
      mediaUrlsFromEvent(variant).some((url) => blockedMediaUrls.has(url)),
    )
  ) {
    return true;
  }

  const blockedDomains = new Set(manifest.blockedDomains);
  if (
    variants.some((variant) =>
      eventUrls(variant)
        .map(domainFromUrl)
        .some((domain) => domain && blockedDomains.has(domain)),
    )
  ) {
    return true;
  }

  const blockedContentFingerprints = new Set(manifest.blockedContentFingerprints);
  return variants.some((variant) =>
    blockedContentFingerprints.has(contentFingerprint(variant.content)),
  );
}

function isRootNote(event) {
  return event.kind === 1 && !(event.tags || []).some((tag) => tag[0] === "e");
}

function sinceFromAgeHours(ageHours) {
  return Math.floor(Date.now() / 1000) - ageHours * 60 * 60;
}

function normalizeRelayUrl(url) {
  return url.replace(/\/+$/, "");
}

async function connectRelays(urls) {
  const relays = await Promise.all(
    urls.map(async (url) => {
      try {
        return await Relay.connect(url);
      } catch {
        return null;
      }
    }),
  );
  return relays.filter(Boolean);
}

function closeRelays(relays) {
  relays.forEach((relay) => {
    try {
      relay.close();
    } catch {
      // Relay already closed.
    }
  });
}

async function subscribeOnce(relays, filter, relayUrls) {
  const targetRelays = relayUrls
    ? relays.filter((relay) =>
        relayUrls.some((url) => normalizeRelayUrl(url) === normalizeRelayUrl(relay.url)),
      )
    : relays;

  if (targetRelays.length === 0) return [];

  const events = [];
  const seenIds = new Set();

  await new Promise((resolve) => {
    const subscriptions = [];
    let eoseCount = 0;
    let settled = false;

    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      subscriptions.forEach((sub) => {
        try {
          sub.close();
        } catch {
          // Subscription already closed.
        }
      });
      resolve();
    };

    const timer = setTimeout(finish, snapshotTimeoutMs);

    for (const relay of targetRelays) {
      try {
        const sub = relay.subscribe([filter], {
          onevent(event) {
            if (seenIds.has(event.id)) return;
            seenIds.add(event.id);
            events.push(event);
          },
          oneose() {
            eoseCount += 1;
            if (eoseCount >= targetRelays.length) finish();
          },
        });
        subscriptions.push(sub);
      } catch {
        eoseCount += 1;
        if (eoseCount >= targetRelays.length) finish();
      }
    }
  });

  return events;
}

function buildReplyFilter(parentIds, since) {
  const ids = parentIds.slice(0, 50);
  if (ids.length === 0) return null;
  return {
    "#e": ids,
    kinds: [1],
    since,
    limit: 100,
  };
}

async function fetchGlobalFeedEvents() {
  const relays = await connectRelays(threadRelays);
  try {
    const notes = new Set();
    const since = sinceFromAgeHours(snapshotAgeHours);
    const rootEvents = await subscribeOnce(
      relays,
      { kinds: [1, 1068], since, limit: 500 },
      powRelays,
    );

    rootEvents.forEach((event) => {
      if (isRootNote(event)) notes.add(event.id);
    });

    const replyEvents = [];
    const seenReplyIds = new Set();
    let parentIds = [...notes];

    for (let depth = 0; depth < replyFetchDepth && parentIds.length > 0; depth += 1) {
      const replyFilter = buildReplyFilter(parentIds, since);
      if (!replyFilter) break;
      const nextReplies = await subscribeOnce(relays, replyFilter, threadRelays);
      const nextParentIds = [];
      nextReplies.forEach((event) => {
        if (seenReplyIds.has(event.id)) return;
        seenReplyIds.add(event.id);
        replyEvents.push(event);
        nextParentIds.push(event.id);
      });
      parentIds = nextParentIds;
    }

    return [...new Map([...rootEvents, ...replyEvents].map((event) => [event.id, event])).values()];
  } finally {
    closeRelays(relays);
  }
}

function buildRepliesByParent(events) {
  const repliesByParent = new Map();
  events.forEach((event) => {
    if (event.kind !== 1) return;
    (event.tags || []).forEach((tag) => {
      if (tag[0] !== "e" || !tag[1]) return;
      const replies = repliesByParent.get(tag[1]) || [];
      replies.push(event);
      repliesByParent.set(tag[1], replies);
    });
  });
  return repliesByParent;
}

function collectThreadReplies(rootId, repliesByParent) {
  const replies = [];
  const seen = new Set();
  const pending = [...(repliesByParent.get(rootId) || [])];
  while (pending.length > 0) {
    const reply = pending.shift();
    if (!reply || seen.has(reply.id)) continue;
    seen.add(reply.id);
    replies.push(reply);
    pending.push(...(repliesByParent.get(reply.id) || []));
  }
  return replies;
}

function eventWork(event) {
  return Math.pow(2, eventPow(event));
}

function workScoreBreakdown(event, replies) {
  let rankingReplyCount = 0;
  const replyWork = replies.reduce((sum, reply) => {
    const difficulty = eventPow(reply);
    if (difficulty < minPow) return sum;
    rankingReplyCount += 1;
    return sum + Math.pow(2, difficulty);
  }, 0);
  const rootWork = eventWork(event);
  return {
    rootWork,
    replyWork,
    totalWork: rootWork + replyWork,
    rankingReplyCount,
  };
}

function processFeedEvents(events) {
  const repliesByParent = buildRepliesByParent(events);
  const seenPubkeys = new Set();
  const posts = [];

  events.forEach((event) => {
    if (event.kind !== 1 && event.kind !== 1068) return;
    if (seenPubkeys.has(event.pubkey)) return;
    if (event.kind === 1 && !isRootNote(event)) return;
    if (eventPow(event) < minPow) return;
    seenPubkeys.add(event.pubkey);
    posts.push(event);
  });

  return posts
    .map((postEvent) => {
      const replies = collectThreadReplies(postEvent.id, repliesByParent);
      return {
        postEvent,
        replies,
        threadReplyCount: replies.length,
        ...workScoreBreakdown(postEvent, replies),
      };
    })
    .sort((a, b) => b.totalWork - a.totalWork || b.postEvent.created_at - a.postEvent.created_at);
}

function parseProfileEvent(event) {
  if (event.kind !== 0) return null;
  try {
    const raw = JSON.parse(event.content);
    const profile = {
      name: typeof raw.name === "string" && raw.name.trim() ? raw.name.trim() : undefined,
      displayName:
        typeof raw.display_name === "string" && raw.display_name.trim()
          ? raw.display_name.trim()
          : typeof raw.displayName === "string" && raw.displayName.trim()
            ? raw.displayName.trim()
            : undefined,
      picture: undefined,
    };
    if (typeof raw.picture === "string") {
      const picture = normalizeUrl(raw.picture.trim());
      if (picture) profile.picture = picture;
    }
    return profile.name || profile.displayName || profile.picture ? profile : null;
  } catch {
    return null;
  }
}

async function fetchProfileMetadata(pubkeys) {
  if (pubkeys.length === 0) return {};
  const relays = await connectRelays(threadRelays);
  try {
    const events = await subscribeOnce(
      relays,
      {
        authors: pubkeys,
        kinds: [0],
        limit: Math.min(pubkeys.length, 250),
      },
      threadRelays,
    );

    const profiles = {};
    events.forEach((event) => {
      const profile = parseProfileEvent(event);
      if (!profile) return;
      const existing = profiles[event.pubkey];
      if (existing && existing.createdAt >= event.created_at) return;
      profiles[event.pubkey] = { profile, createdAt: event.created_at };
    });

    return Object.fromEntries(
      Object.entries(profiles).map(([pubkey, entry]) => [pubkey, entry.profile]),
    );
  } finally {
    closeRelays(relays);
  }
}

async function loadSnapshotFromDisk() {
  try {
    const cached = JSON.parse(await readFile(snapshotCacheFile, "utf8"));
    if (
      typeof cached.fetchedAt === "number" &&
      Array.isArray(cached.processedEvents) &&
      cached.profiles &&
      typeof cached.profiles === "object"
    ) {
      snapshot = cached;
    }
  } catch {
    // The cache is optional.
  }
}

async function persistSnapshot(nextSnapshot) {
  await mkdir(path.dirname(snapshotCacheFile), { recursive: true });
  await writeFile(snapshotCacheFile, JSON.stringify(nextSnapshot), "utf8");
}

async function fetchFeedSnapshot() {
  const events = await fetchGlobalFeedEvents();
  const manifest = await getModerationManifest();
  const visibleEvents =
    manifest.updatedAt === 0 ? events : events.filter((event) => !isEventModerated(event, manifest));
  const processedEvents = processFeedEvents(visibleEvents);
  const pubkeys = [...new Set(processedEvents.map((processed) => processed.postEvent.pubkey))];
  const profiles = await fetchProfileMetadata(pubkeys);

  return {
    fetchedAt: Date.now(),
    processedEvents,
    profiles,
  };
}

async function refreshSnapshot() {
  if (refreshPromise) return refreshPromise;

  refreshPromise = fetchFeedSnapshot()
    .then(async (nextSnapshot) => {
      snapshot = nextSnapshot;
      lastRefreshError = null;
      await persistSnapshot(nextSnapshot);
      return nextSnapshot;
    })
    .catch((error) => {
      lastRefreshError = error instanceof Error ? error.message : "refresh failed";
      throw error;
    })
    .finally(() => {
      refreshPromise = null;
    });

  return refreshPromise;
}

function snapshotStatus() {
  return {
    fetchedAt: snapshot?.fetchedAt || null,
    postCount: snapshot?.processedEvents?.length || 0,
    profileCount: snapshot ? Object.keys(snapshot.profiles).length : 0,
    refreshing: Boolean(refreshPromise),
    lastRefreshError,
    refreshSeconds,
    ageHours: snapshotAgeHours,
    timeoutMs: snapshotTimeoutMs,
    powRelays,
    enrichmentRelays,
    cacheFile: snapshotCacheFile,
  };
}

function handleClientConnection(client) {
  stats.activeClients += 1;
  stats.totalConnections += 1;
  addRecent("client-connected", `${stats.activeClients} active`);

  const backend = new WebSocket(backendUrl);
  const queued = [];

  backend.on("open", () => {
    stats.lastBackendOpenAt = Date.now();
    while (queued.length > 0 && backend.readyState === WebSocket.OPEN) {
      backend.send(queued.shift());
    }
  });

  backend.on("message", (data) => {
    stats.backendMessages += 1;
    const raw = data.toString();
    const msg = safeJsonParse(raw);

    if (Array.isArray(msg) && msg[0] === "OK") {
      const ok = msg[2] === true;
      if (ok) {
        stats.acceptedPublishes += 1;
        addRecent("accepted", msg[1]);
      } else {
        stats.backendRejectedPublishes += 1;
        addRecent("backend-rejected", `${msg[1]}: ${msg[3] || ""}`);
      }
    }

    if (client.readyState === WebSocket.OPEN) {
      client.send(raw);
    }
  });

  backend.on("error", (error) => {
    stats.lastBackendErrorAt = Date.now();
    addRecent("backend-error", error.message);
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(["NOTICE", "error: relay backend unavailable"]));
    }
  });

  backend.on("close", () => {
    if (client.readyState === WebSocket.OPEN) {
      client.close(1011, "relay backend closed");
    }
  });

  client.on("message", (data) => {
    stats.clientMessages += 1;
    const raw = data.toString();
    const msg = safeJsonParse(raw);

    if (!Array.isArray(msg) || typeof msg[0] !== "string") {
      stats.malformedMessages += 1;
      addRecent("malformed", "invalid nostr message");
      client.send(JSON.stringify(["NOTICE", "invalid: malformed nostr message"]));
      return;
    }

    if (msg[0] === "EVENT") {
      stats.publishAttempts += 1;
      const event = msg[1];
      const result = verifyPow(event);

      if (!result.ok) {
        stats.powRejectedPublishes += 1;
        addRecent("pow-rejected", `${event?.id || "unknown"}: ${result.reason}`);
        sendOk(client, event?.id, false, `pow: ${result.reason}`);
        return;
      }

      addRecent("publish", summarizeEvent(event, result.pow));
    } else if (msg[0] === "REQ" || msg[0] === "COUNT") {
      stats.reqMessages += 1;
    } else if (msg[0] === "CLOSE") {
      stats.closeMessages += 1;
    }

    if (backend.readyState === WebSocket.OPEN) {
      backend.send(raw);
    } else if (backend.readyState === WebSocket.CONNECTING) {
      queued.push(raw);
    } else {
      client.send(JSON.stringify(["NOTICE", "error: relay backend unavailable"]));
    }
  });

  client.on("close", () => {
    stats.activeClients = Math.max(0, stats.activeClients - 1);
    addRecent("client-closed", `${stats.activeClients} active`);
    if (backend.readyState === WebSocket.OPEN || backend.readyState === WebSocket.CONNECTING) {
      backend.close();
    }
  });
}

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

app.disable("x-powered-by");
app.use(express.json({ limit: "128kb" }));
app.use((req, res, next) => {
  setSecurityHeaders(res);
  setCorsHeaders(res);

  if (isPublicHost(req) && !isPublicHttpRouteAllowed(req)) {
    res.status(404).json({ error: "not found" });
    return;
  }

  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }

  next();
});

app.get("/api/status", async (_req, res) => {
  const actions = await getModerationActions();
  const manifest = manifestFromActions(actions);
  const confessStore = await readConfessStore();
  const confessSecretKey = parseConfessSecretKey();
  res.json({
    ...stats,
    uptimeSeconds: Math.floor((Date.now() - stats.startedAt) / 1000),
    relayInfo,
    snapshot: snapshotStatus(),
    confess: {
      ...confessStatusFromStore(confessStore),
      storeFile: confessStoreFile,
      relays: confessRelays,
      linkedPubkey: confessSecretKey ? getPublicKey(confessSecretKey) : null,
    },
    moderation: {
      actionCount: actions.length,
      manifest,
      storeFile: moderationStoreFile,
    },
    generatedAt: Date.now(),
    instanceId: crypto
      .createHash("sha256")
      .update(`${stats.startedAt}:${backendUrl}`)
      .digest("hex")
      .slice(0, 12),
  });
});

app.get("/api/feed/bootstrap", async (_req, res) => {
  res.setHeader("Cache-Control", "public, max-age=120, stale-while-revalidate=300");
  if (snapshot) {
    res.json(snapshot);
    return;
  }

  try {
    res.json(await refreshSnapshot());
  } catch {
    res.status(503).json({
      error: "bootstrap unavailable",
      lastRefreshError,
    });
  }
});

app.get("/api/cron/refresh-feed", async (req, res) => {
  if (!isCronAuthorized(req)) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }

  try {
    const nextSnapshot = await refreshSnapshot();
    res.json({
      ok: true,
      fetchedAt: nextSnapshot.fetchedAt,
      postCount: nextSnapshot.processedEvents.length,
      profileCount: Object.keys(nextSnapshot.profiles).length,
    });
  } catch {
    res.status(500).json({ error: lastRefreshError || "refresh failed" });
  }
});

app.get("/healthz", (_req, res) => {
  res.status(snapshot ? 200 : 503).json({
    ok: Boolean(snapshot),
    ...snapshotStatus(),
  });
});

app.get("/api/confess/status", async (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.json(confessStatusFromStore(await readConfessStore()));
});

app.post("/api/confess", async (req, res) => {
  try {
    const result = await createConfession(req.body?.event);
    res.status(201).json({ ok: true, ...result });
  } catch (error) {
    const statusCode =
      typeof error?.statusCode === "number" ? error.statusCode : 500;
    res.status(statusCode).json({
      error: error instanceof Error ? error.message : "confess failed",
      pow: typeof error?.pow === "number" ? error.pow : undefined,
    });
  }
});

app.get("/api/moderation/manifest", async (_req, res) => {
  res.setHeader("Cache-Control", "public, max-age=15, stale-while-revalidate=45");
  res.json(await getModerationManifest());
});

app.get("/api/moderation/actions", async (req, res) => {
  if (!isAdminAuthorized(req)) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }
  res.json({ actions: await getModerationActions() });
});

app.post("/api/moderation/actions", async (req, res) => {
  if (!isAdminAuthorized(req)) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }

  try {
    const action = await createModerationAction(req.body || {});
    void refreshSnapshot().catch(() => {
      console.error(lastRefreshError || "moderation refresh failed");
    });
    res.status(201).json({ action });
  } catch (error) {
    res.status(400).json({
      error: error instanceof Error ? error.message : "invalid action",
    });
  }
});

app.delete("/api/moderation/actions/:id", async (req, res) => {
  if (!isAdminAuthorized(req)) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }

  try {
    const action = await deleteModerationAction(req.params.id);
    void refreshSnapshot().catch(() => {
      console.error(lastRefreshError || "moderation refresh failed");
    });
    res.json({ action });
  } catch (error) {
    res.status(404).json({
      error: error instanceof Error ? error.message : "not found",
    });
  }
});

app.get("/", (req, res, next) => {
  const accept = String(req.headers.accept || "");
  if (accept.includes("application/nostr+json")) {
    res.type("application/nostr+json").json(relayInfo);
    return;
  }
  next();
});

app.use(
  express.static(path.join(__dirname, "public"), {
    extensions: ["html"],
    setHeaders(res) {
      res.setHeader("Cache-Control", "no-store");
    },
  }),
);

server.on("upgrade", (request, socket, head) => {
  const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);
  if (url.pathname !== "/" && url.pathname !== "/relay") {
    socket.destroy();
    return;
  }

  wss.handleUpgrade(request, socket, head, (ws) => {
    handleClientConnection(ws);
  });
});

await mkdir(dataDir, { recursive: true });
await loadSnapshotFromDisk();

server.listen(port, "0.0.0.0", () => {
  console.log(`Wired Admin gateway listening on ${port}`);
  console.log(`Proxying Nostr traffic to ${backendUrl}`);
  console.log(`Feed snapshot cache: ${snapshotCacheFile}`);
});

void refreshSnapshot().catch(() => {
  if (!snapshot) console.error(lastRefreshError || "initial refresh failed");
});

if (refreshSeconds > 0) {
  setInterval(() => {
    void refreshSnapshot().catch(() => {
      console.error(lastRefreshError || "scheduled refresh failed");
    });
  }, refreshSeconds * 1000).unref();
}
