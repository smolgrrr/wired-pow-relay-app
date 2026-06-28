# Wired PoW Relay Umbrel App

Community Umbrel app store for a Wired-oriented Nostr proof-of-work relay.

The app runs a `strfry` relay as the durable backend and exposes a small Node
gateway that:

- serves a local Umbrel relay, feed snapshot, and moderation console,
- exposes NIP-11 relay metadata,
- proxies Nostr WebSocket traffic to `strfry`,
- rejects publish attempts that do not meet the configured NIP-13 PoW floor,
- serves a Wired-compatible feed bootstrap snapshot at `/api/feed/bootstrap`,
- serves public client-side moderation filtering data at `/api/moderation/manifest`,
- keeps moderation management actions local to the Umbrel app.

Persistent app data is stored under Umbrel app data:

- `data/strfry` for the relay database,
- `data/web/feed-bootstrap.json` for the feed snapshot cache,
- `data/web/moderation.json` for moderation actions.

The community app enables `MODERATION_ADMIN_OPEN=true` for the local Umbrel
console only. Hosts listed in `PUBLIC_HOSTS` cannot access the UI,
`/api/status`, `/api/cron/refresh-feed`, or `/api/moderation/actions`. Public
hosts only receive Nostr relay/NIP-11 traffic, `/api/feed/bootstrap`, and
`/api/moderation/manifest`. `PUBLIC_HOSTS` supports exact hosts and suffix
patterns such as `*.vercel.app`; Vercel preview deployments are frontend origins
and only need the public snapshot/manifest/relay endpoints.

## Install

Add this repository as a Community App Store in umbrelOS, then install
`Wired PoW Relay`.

## Local development

```sh
cd smolgrrr-wired-pow-relay
docker compose up --build
```

Then open `http://localhost:3000`.
