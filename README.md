# Wired PoW Relay Umbrel App

Community Umbrel app store for a Wired-oriented Nostr proof-of-work relay.

The app runs a `strfry` relay as the durable backend and exposes a small Node
gateway that:

- serves a relay, feed snapshot, and moderation console,
- exposes NIP-11 relay metadata,
- proxies Nostr WebSocket traffic to `strfry`,
- rejects publish attempts that do not meet the configured NIP-13 PoW floor,
- serves a Wired-compatible feed bootstrap snapshot at `/api/feed/bootstrap`,
- serves moderation manifest/actions APIs at `/api/moderation/*`.

Persistent app data is stored under Umbrel app data:

- `data/strfry` for the relay database,
- `data/web/feed-bootstrap.json` for the feed snapshot cache,
- `data/web/moderation.json` for moderation actions.

The community app currently enables `MODERATION_ADMIN_OPEN=true` so the local
Umbrel console can create moderation actions without a separate token. Before
publishing the console on a public hostname, remove that flag and set
`MODERATION_ADMIN_TOKEN`, or put the admin action paths behind Cloudflare Access.

## Install

Add this repository as a Community App Store in umbrelOS, then install
`Wired PoW Relay`.

## Local development

```sh
cd smolgrrr-wired-pow-relay
docker compose up --build
```

Then open `http://localhost:3000`.
