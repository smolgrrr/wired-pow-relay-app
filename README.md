# Wired Admin Umbrel App

Community Umbrel app store for Wired's relay, snapshot, and moderation admin service.

The app runs a `strfry` relay as the durable backend and exposes a small Node
gateway that:

- serves a local Umbrel relay, feed snapshot, and moderation console,
- exposes NIP-11 relay metadata,
- proxies Nostr WebSocket traffic to `strfry`,
- rejects publish attempts that do not meet the configured NIP-13 PoW floor,
- serves a Wired feed bootstrap snapshot at `/api/feed/bootstrap`,
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
patterns such as `*.vercel.app` and `*.onion`; Vercel preview deployments are
frontend origins and only need the public snapshot/manifest/relay endpoints.

## Install

Add this repository as a Community App Store in umbrelOS, then install
`Wired Admin`.

## Local development

```sh
cd smolgrrr-wired-admin
docker compose up --build
```

Then open `http://localhost:3000`.

## Confess X Mirror

The Confess X mirror is server-side only and disabled by default. A Confess
submission publishes to Nostr first; X posting is queued afterward and X
rejection or downtime does not block the Nostr confession.

The mirror uses X OAuth1 user-context credentials generated for the dedicated X
account. OAuth2 is not used.

Runtime environment:

- `CONFESS_X_ENABLED`: set `true` to queue mirror attempts.
- `CONFESS_X_DRY_RUN`: defaults to `true`; set `false` only when ready to post.
- `CONFESS_X_OAUTH1_API_KEY`: app API key.
- `CONFESS_X_OAUTH1_API_SECRET`: app API key secret.
- `CONFESS_X_OAUTH1_ACCESS_TOKEN`: dedicated account access token.
- `CONFESS_X_OAUTH1_ACCESS_SECRET`: dedicated account access token secret.
- `CONFESS_X_ACCOUNT_HANDLE`: optional operator label for status output.

Before posting, the backend applies conservative X safety gates: no links/media,
no X mentions, no hashtags/cashtags, no obvious private information, and strict
blocking for high-risk harassment, threats, self-harm encouragement, scams, and
sexual-minor patterns. Blocked X mirrors are recorded on the Confess ledger but
the Nostr event remains published.
