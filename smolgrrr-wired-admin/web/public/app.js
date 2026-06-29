const fields = [
  "activeClients",
  "publishAttempts",
  "acceptedPublishes",
  "powRejectedPublishes",
  "backendRejectedPublishes",
  "reqMessages",
  "backendUrl",
];

const ids = [
  ...fields,
  "health",
  "endpoint",
  "minPow",
  "postCount",
  "profileCount",
  "refreshing",
  "ageHours",
  "refreshSeconds",
  "bootstrapUrl",
  "snapshotFetchedAt",
  "powRelays",
  "enrichmentRelays",
  "lastRefreshError",
  "software",
  "nips",
  "activity",
  "actions",
  "updatedAt",
  "moderationSummary",
  "manifestUpdatedAt",
  "moderationForm",
  "formStatus",
  "refreshSnapshot",
];

const elements = Object.fromEntries(ids.map((id) => [id, document.getElementById(id)]));

function formatDuration(seconds) {
  const mins = Math.floor(seconds / 60);
  const hours = Math.floor(mins / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) return `${days}d ${hours % 24}h`;
  if (hours > 0) return `${hours}h ${mins % 60}m`;
  if (mins > 0) return `${mins}m`;
  return `${seconds}s`;
}

function formatTime(value) {
  if (!value) return "--";
  return new Date(value).toLocaleString();
}

function relayEndpoint(path = "/") {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}${path}`;
}

function httpEndpoint(path) {
  return `${window.location.origin}${path}`;
}

function renderRecent(items) {
  elements.activity.innerHTML = "";
  const recent =
    items.length > 0
      ? items
      : [{ at: Date.now(), type: "idle", detail: "waiting for relay activity" }];

  for (const item of recent) {
    elements.activity.append(activityItem(item.at, item.type, item.detail));
  }
}

function activityItem(at, type, detail) {
  const li = document.createElement("li");
  const time = document.createElement("time");
  const body = document.createElement("div");
  const heading = document.createElement("strong");
  const code = document.createElement("code");

  time.textContent = formatTime(at);
  heading.textContent = type;
  code.textContent = typeof detail === "string" ? detail : JSON.stringify(detail);

  body.append(heading, code);
  li.append(time, body);
  return li;
}

function renderActions(actions) {
  elements.actions.innerHTML = "";
  if (!actions.length) {
    elements.actions.append(activityItem(Date.now(), "empty", "no moderation actions"));
    return;
  }

  for (const action of actions) {
    const item = activityItem(
      action.createdAt,
      `${action.kind} / ${action.reason}`,
      `${action.value}${action.note ? ` - ${action.note}` : ""}`,
    );
    const button = document.createElement("button");
    button.className = "button danger delete-action";
    button.type = "button";
    button.textContent = "Remove";
    button.addEventListener("click", () => deleteAction(action.id));
    item.append(button);
    elements.actions.append(item);
  }
}

async function deleteAction(id) {
  elements.formStatus.textContent = "Removing";
  const response = await fetch(`/api/moderation/actions/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    elements.formStatus.textContent = data.error || `HTTP ${response.status}`;
    return;
  }

  elements.formStatus.textContent = "Action removed";
  await Promise.all([refresh(), fetchActions()]);
}

async function fetchActions() {
  const response = await fetch("/api/moderation/actions", { cache: "no-store" });
  if (!response.ok) {
    renderActions([]);
    elements.formStatus.textContent =
      response.status === 401 ? "Admin actions require MODERATION_ADMIN_TOKEN." : "";
    return;
  }
  const data = await response.json();
  renderActions(data.actions || []);
}

async function refresh() {
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    const snapshot = data.snapshot || {};
    const moderation = data.moderation || {};
    const manifest = moderation.manifest || {};

    elements.health.textContent = "online";
    elements.health.className = "status-pill ok";
    elements.endpoint.textContent = relayEndpoint("/");
    elements.minPow.textContent = data.minPow;
    elements.postCount.textContent = snapshot.postCount ?? 0;
    elements.profileCount.textContent = snapshot.profileCount ?? 0;
    elements.refreshing.textContent = snapshot.refreshing ? "yes" : "no";
    elements.ageHours.textContent = `${snapshot.ageHours ?? "--"}h`;
    elements.refreshSeconds.textContent = formatDuration(snapshot.refreshSeconds || 0);
    elements.bootstrapUrl.textContent = httpEndpoint("/api/feed/bootstrap");
    elements.snapshotFetchedAt.textContent = formatTime(snapshot.fetchedAt);
    elements.powRelays.textContent = (snapshot.powRelays || []).join(", ");
    elements.enrichmentRelays.textContent = (snapshot.enrichmentRelays || []).join(", ");
    elements.lastRefreshError.textContent = snapshot.lastRefreshError || "--";
    elements.software.textContent = `${data.relayInfo.software} ${data.relayInfo.version}`;
    elements.nips.textContent = data.relayInfo.supported_nips.join(", ");
    elements.updatedAt.textContent = `updated ${new Date(data.generatedAt).toLocaleTimeString()}`;
    elements.moderationSummary.textContent = `${moderation.actionCount || 0} actions`;
    elements.manifestUpdatedAt.textContent = manifest.updatedAt
      ? `manifest ${formatTime(manifest.updatedAt)}`
      : "manifest empty";

    for (const field of fields) {
      if (elements[field]) elements[field].textContent = data[field];
    }

    renderRecent(data.recent || []);
  } catch (error) {
    elements.health.textContent = "offline";
    elements.health.className = "status-pill bad";
    elements.updatedAt.textContent = error.message;
  }
}

async function refreshSnapshot() {
  elements.refreshSnapshot.disabled = true;
  elements.refreshSnapshot.textContent = "Refreshing";
  try {
    await fetch("/api/cron/refresh-feed", { cache: "no-store" });
    await refresh();
  } finally {
    elements.refreshSnapshot.disabled = false;
    elements.refreshSnapshot.textContent = "Refresh now";
  }
}

function setupTabs() {
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((item) => item.classList.remove("active"));
      document
        .querySelectorAll(".tab-panel")
        .forEach((panel) => panel.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById(`tab-${tab.dataset.tab}`).classList.add("active");
    });
  });
}

function setupModerationForm() {
  elements.moderationForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const formData = new FormData(elements.moderationForm);
    elements.formStatus.textContent = "Saving";

    const response = await fetch("/api/moderation/actions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(Object.fromEntries(formData.entries())),
    });

    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      elements.formStatus.textContent = data.error || `HTTP ${response.status}`;
      return;
    }

    elements.moderationForm.reset();
    elements.formStatus.textContent = "Action added";
    await Promise.all([refresh(), fetchActions()]);
  });
}

setupTabs();
setupModerationForm();
elements.refreshSnapshot.addEventListener("click", refreshSnapshot);

refresh();
fetchActions();
setInterval(refresh, 2500);
setInterval(fetchActions, 10000);
