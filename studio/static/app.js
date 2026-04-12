const state = {
  sessions: [],
  currentSessionId: null,
  currentSession: null,
  activeTaskId: null,
  pollHandle: null,
  refreshHandle: null,
  lastAutoSyncAt: 0,
};

const el = {
  sessionForm: document.querySelector("#sessionForm"),
  sessionLabel: document.querySelector("#sessionLabel"),
  sessionList: document.querySelector("#sessionList"),
  refreshSessions: document.querySelector("#refreshSessions"),
  cloneSession: document.querySelector("#cloneSession"),
  sessionTitle: document.querySelector("#sessionTitle"),
  sessionUpdated: document.querySelector("#sessionUpdated"),
  sessionWorkspace: document.querySelector("#sessionWorkspace"),
  sessionOverview: document.querySelector("#sessionOverview"),
  stageOverview: document.querySelector("#stageOverview"),
  fleetStatusChip: document.querySelector("#fleetStatusChip"),
  fleetSummary: document.querySelector("#fleetSummary"),
  fleetInstances: document.querySelector("#fleetInstances"),
  emptyState: document.querySelector("#emptyState"),
  commandDeck: document.querySelector("#commandDeck"),
  taskStatus: document.querySelector("#taskStatus"),
  taskMeta: document.querySelector("#taskMeta"),
  taskLog: document.querySelector("#taskLog"),
  artifactGrid: document.querySelector("#artifactGrid"),
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || "Request failed");
  }
  return payload;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[char]));
}

function formatDate(value) {
  if (!value) return "unknown";
  const date = typeof value === "number" ? new Date(value * 1000) : new Date(value);
  return date.toLocaleString();
}

function formatMoney(value) {
  if (value === null || value === undefined || value === "") return "—";
  return `$${Number(value).toFixed(2)}`;
}

function classForStatus(status) {
  if (status === "running" || status === "active") return "running";
  if (status === "completed" || status === "complete") return "completed";
  if (status === "failed") return "failed";
  if (status === "ready") return "warning";
  return "muted";
}

function findArtifact(artifacts, name) {
  return artifacts?.find((artifact) => artifact.name === name);
}

function renderSessions() {
  if (!state.sessions.length) {
    el.sessionList.innerHTML = `<div class="artifact-empty">No sessions yet.</div>`;
    return;
  }

  el.sessionList.innerHTML = state.sessions
    .map((session) => {
      const stageStatus = session.overview?.stages?.find((stage) => stage.status === "active")?.label || "Idle";
      return `
        <button class="session-item ${session.id === state.currentSessionId ? "active" : ""}" data-session-id="${session.id}">
          <strong>${escapeHtml(session.label)}</strong>
          <small>${session.artifacts.length} artifacts · ${stageStatus} · updated ${formatDate(session.updated_at)}</small>
        </button>
      `;
    })
    .join("");

  document.querySelectorAll(".session-item").forEach((button) => {
    button.addEventListener("click", () => selectSession(button.dataset.sessionId));
  });
}

function renderTask(task) {
  if (!task) {
    el.taskStatus.textContent = "No task";
    el.taskStatus.className = "chip muted";
    el.taskMeta.classList.add("hidden");
    el.taskMeta.innerHTML = "";
    el.taskLog.textContent = "Waiting for a session.";
    return;
  }

  el.taskStatus.textContent = `${task.command} · ${task.status}`;
  el.taskStatus.className = `chip ${classForStatus(task.status)}`;
  el.taskMeta.classList.remove("hidden");
  el.taskMeta.innerHTML = [
    `<span class="chip mono">${escapeHtml(task.id)}</span>`,
    `<span class="chip muted">started ${task.started_at ? formatDate(task.started_at) : "queued"}</span>`,
    task.finished_at ? `<span class="chip muted">finished ${formatDate(task.finished_at)}</span>` : "",
    task.exit_code !== null ? `<span class="chip muted">exit ${task.exit_code}</span>` : "",
  ]
    .filter(Boolean)
    .join("");
  el.taskLog.textContent = task.logs?.length ? task.logs.join("\n") : "Task started. Waiting for output…";
}

function summarizeObject(summary) {
  if (!summary || typeof summary !== "object") return "";
  return Object.entries(summary)
    .filter(([, value]) => value !== null && value !== undefined && value !== "")
    .map(
      ([key, value]) => `
        <div class="kv">
          <span>${escapeHtml(key.replaceAll("_", " "))}</span>
          <span>${escapeHtml(Array.isArray(value) ? value.join(", ") : value)}</span>
        </div>
      `
    )
    .join("");
}

function artifactDownloadLink(sessionId, name) {
  return `/api/sessions/${encodeURIComponent(sessionId)}/artifacts/${encodeURIComponent(name)}`;
}

function renderArtifacts(artifacts) {
  if (!artifacts?.length) {
    el.artifactGrid.innerHTML = `<div class="artifact-empty">No artifacts yet.</div>`;
    return;
  }

  el.artifactGrid.innerHTML = artifacts
    .map((artifact) => {
      const summary = summarizeObject(artifact.summary);
      const content = artifact.kind === "json" ? JSON.stringify(artifact.data, null, 2) : artifact.content || "";
      return `
        <article class="artifact-card">
          <div class="artifact-head">
            <div>
              <h4>${escapeHtml(artifact.name)}</h4>
              <p class="artifact-meta">${escapeHtml(artifact.kind)} · ${artifact.size} bytes · ${formatDate(artifact.updated_at)}</p>
            </div>
            <a class="artifact-download" href="${artifactDownloadLink(state.currentSessionId, artifact.name)}">download</a>
          </div>
          ${summary ? `<div class="artifact-summary">${summary}</div>` : ""}
          ${
            content
              ? `<pre class="artifact-content">${escapeHtml(content)}</pre>`
              : ""
          }
        </article>
      `;
    })
    .join("");
}

function renderSessionOverview(overview) {
  if (!overview) {
    el.sessionOverview.classList.add("hidden");
    el.sessionOverview.innerHTML = "";
    return;
  }
  el.sessionOverview.classList.remove("hidden");
  el.sessionOverview.innerHTML = `
    <div class="overview-grid">
      <article class="overview-card">
        <span>Config</span>
        <strong>${escapeHtml(overview.config || "—")}</strong>
      </article>
      <article class="overview-card">
        <span>Funding mode</span>
        <strong>${escapeHtml(overview.funding_mode || "—")}</strong>
      </article>
      <article class="overview-card">
        <span>Script size</span>
        <strong>${overview.script_size ? `${overview.script_size} bytes` : "—"}</strong>
      </article>
      <article class="overview-card">
        <span>Estimated cost</span>
        <strong>${overview.benchmark_cost_usd ? formatMoney(overview.benchmark_cost_usd) : "Run benchmark"}</strong>
      </article>
    </div>
  `;
}

function renderStageOverview(overview) {
  const stages = overview?.stages || [];
  if (!stages.length) {
    el.stageOverview.innerHTML = `<div class="artifact-empty">Create or load a session to see the phase map.</div>`;
    return;
  }
  el.stageOverview.innerHTML = stages
    .map(
      (stage, index) => `
        <article class="stage-pill ${classForStatus(stage.status)}">
          <div class="stage-pill-index">${index + 1}</div>
          <div>
            <strong>${escapeHtml(stage.label)}</strong>
            <p>${escapeHtml(stage.detail)}</p>
          </div>
          <span class="chip ${classForStatus(stage.status)}">${escapeHtml(stage.status)}</span>
        </article>
      `
    )
    .join("");
}

function renderFleet(session) {
  const fleetArtifact = findArtifact(session?.artifacts, "qsb_fleet_status.json");
  const fleet = fleetArtifact?.data || session?.overview?.fleet || null;
  if (!fleet) {
    el.fleetStatusChip.textContent = "No fleet";
    el.fleetStatusChip.className = "chip muted";
    el.fleetSummary.innerHTML = `<div class="artifact-empty">No fleet status yet.</div>`;
    el.fleetInstances.innerHTML = "";
    return;
  }

  el.fleetStatusChip.textContent = `${fleet.stage || "fleet"} · ${fleet.phase || "unknown"}`;
  el.fleetStatusChip.className = `chip ${classForStatus(fleet.phase === "monitoring" ? "running" : fleet.phase)}`;
  el.fleetSummary.innerHTML = `
    <div class="overview-grid fleet-grid">
      <article class="overview-card">
        <span>Instances</span>
        <strong>${fleet.active_instances ?? "—"}</strong>
      </article>
      <article class="overview-card">
        <span>Spent so far</span>
        <strong>${formatMoney(fleet.cost_so_far)}</strong>
      </article>
      <article class="overview-card">
        <span>Hourly burn</span>
        <strong>${formatMoney(fleet.fleet_hourly)}</strong>
      </article>
      <article class="overview-card">
        <span>Estimated rate</span>
        <strong>${fleet.fleet_rate_est_mhs ? `${fleet.fleet_rate_est_mhs.toFixed ? fleet.fleet_rate_est_mhs.toFixed(0) : fleet.fleet_rate_est_mhs} M/s` : "—"}</strong>
      </article>
    </div>
  `;
  el.fleetInstances.innerHTML = (fleet.instances || [])
    .map((entry) => {
      const shard =
        entry.first_start !== null && entry.first_start !== undefined && entry.first_end !== null && entry.first_end !== undefined
          ? `first [${entry.first_start}, ${entry.first_end})`
          : "";
      return `
        <article class="fleet-instance ${classForStatus(entry.status)}">
          <div class="fleet-instance-head">
            <strong>M${escapeHtml(entry.machine_id)}</strong>
            <span class="chip ${classForStatus(entry.status)}">${escapeHtml(entry.status)}</span>
          </div>
          <p>${escapeHtml(entry.gpu_name || "Unknown GPU")} · ${entry.num_gpus || "?"} GPUs · ${entry.hourly_price ? formatMoney(entry.hourly_price) + "/hr" : "rate unknown"}</p>
          <p>${escapeHtml(entry.rate || entry.progress || "Waiting for first heartbeat")} ${shard ? `· ${escapeHtml(shard)}` : ""}</p>
        </article>
      `;
    })
    .join("");
}

function renderSession(session) {
  state.currentSession = session;
  state.currentSessionId = session?.id || null;
  renderSessions();

  if (!session) {
    state.activeTaskId = null;
    el.sessionTitle.textContent = "No session selected";
    el.sessionUpdated.textContent = "Idle";
    el.sessionUpdated.className = "chip muted";
    el.sessionWorkspace.textContent = "No workspace";
    el.emptyState.classList.remove("hidden");
    el.commandDeck.classList.add("hidden");
    renderSessionOverview(null);
    renderStageOverview(null);
    renderFleet(null);
    renderArtifacts([]);
    renderTask(null);
    return;
  }

  el.sessionTitle.textContent = session.label;
  el.sessionUpdated.textContent = `Updated ${formatDate(session.updated_at)}`;
  el.sessionUpdated.className = "chip muted";
  el.sessionWorkspace.textContent = session.workspace;
  el.emptyState.classList.add("hidden");
  el.commandDeck.classList.remove("hidden");
  renderSessionOverview(session.overview);
  renderStageOverview(session.overview);
  renderFleet(session);
  renderArtifacts(session.artifacts);
  hydrateFormsFromArtifacts(session.artifacts);

  const latestTask = session.tasks?.[0] || null;
  renderTask(latestTask);
  if (latestTask && latestTask.status === "running") {
    state.activeTaskId = latestTask.id;
    startPolling(latestTask.id);
  } else {
    state.activeTaskId = null;
    stopPolling();
    maybeAutoSync(session);
  }
}

function setFormValue(command, name, value) {
  const input = document.querySelector(`[data-command="${command}"] [name="${name}"]`);
  if (input && value !== undefined && value !== null && value !== "") {
    input.value = Array.isArray(value) ? value.join(",") : value;
  }
}

function hydrateFormsFromArtifacts(artifacts) {
  const stateArtifact = findArtifact(artifacts, "qsb_state.json")?.data;
  if (stateArtifact?.funding_mode) {
    setFormValue("setup", "funding_mode", stateArtifact.funding_mode);
  }

  const pinning = findArtifact(artifacts, "pinning_import.json")?.data;
  if (pinning) {
    setFormValue("export-digest", "sequence", pinning.sequence);
    setFormValue("export-digest", "locktime", pinning.locktime);
    setFormValue("assemble", "sequence", pinning.sequence);
    setFormValue("assemble", "locktime", pinning.locktime);
  }

  const digest1 = findArtifact(artifacts, "digest_r1_import.json")?.data;
  if (digest1?.selected_indices) {
    setFormValue("assemble", "round1", digest1.selected_indices);
  }

  const digest2 = findArtifact(artifacts, "digest_r2_import.json")?.data;
  if (digest2?.selected_indices) {
    setFormValue("assemble", "round2", digest2.selected_indices);
  }
}

async function loadSessions() {
  const payload = await api("/api/sessions");
  state.sessions = payload.sessions;
  renderSessions();
  if (!state.currentSessionId && state.sessions.length) {
    await selectSession(state.sessions[0].id);
  }
}

async function selectSession(sessionId) {
  const session = await api(`/api/sessions/${sessionId}`);
  renderSession(session);
}

function serializeForm(form) {
  const data = new FormData(form);
  const args = {};
  for (const [key, value] of data.entries()) {
    if (typeof value === "string") {
      if (form.querySelector(`[name="${key}"]`)?.type === "checkbox") {
        args[key] = "true";
      } else if (value.trim() !== "") {
        args[key] = value.trim();
      }
    }
  }
  form.querySelectorAll('input[type="checkbox"]').forEach((checkbox) => {
    if (!checkbox.checked) {
      delete args[checkbox.name];
    }
  });
  return args;
}

async function runCommand(command, args = {}) {
  if (!state.currentSessionId) return;
  const task = await api(`/api/sessions/${state.currentSessionId}/commands`, {
    method: "POST",
    body: JSON.stringify({ command, args }),
  });
  state.activeTaskId = task.id;
  renderTask(task);
  startPolling(task.id);
}

async function pollTask(taskId) {
  const payload = await api(`/api/tasks/${taskId}`);
  renderTask(payload);
  renderArtifacts(payload.session.artifacts);
  state.currentSession = payload.session;
  state.currentSessionId = payload.session.id;
  renderSessionOverview(payload.session.overview);
  renderStageOverview(payload.session.overview);
  renderFleet(payload.session);
  renderSessions();
  if (payload.status !== "running") {
    state.activeTaskId = null;
    stopPolling();
    await selectSession(payload.session.id);
  }
}

function startPolling(taskId) {
  stopPolling();
  state.pollHandle = window.setInterval(() => {
    pollTask(taskId).catch((error) => {
      console.error(error);
      stopPolling();
    });
  }, 1200);
}

function stopPolling() {
  if (state.pollHandle) {
    window.clearInterval(state.pollHandle);
    state.pollHandle = null;
  }
}

function startRefreshLoop() {
  if (state.refreshHandle) {
    window.clearInterval(state.refreshHandle);
  }
  state.refreshHandle = window.setInterval(() => {
    if (!state.currentSessionId || state.activeTaskId) return;
    selectSession(state.currentSessionId).catch(console.error);
  }, 8000);
}

function maybeAutoSync(session) {
  const hasFleetState = Boolean(findArtifact(session?.artifacts, "qsb_fleet_state.json"));
  const fleet = findArtifact(session?.artifacts, "qsb_fleet_status.json")?.data;
  const activePhase = fleet ? ["renting", "running", "monitoring"].includes(fleet.phase) : hasFleetState;
  const now = Date.now();
  if (hasFleetState && activePhase && now - state.lastAutoSyncAt > 30000) {
    state.lastAutoSyncAt = now;
    runCommand("vast-sync").catch((error) => {
      console.error(error);
      renderTask({ command: "vast-sync", status: "failed", logs: [String(error.message || error)] });
    });
  }
}

async function createSession(event) {
  event.preventDefault();
  const label = el.sessionLabel.value.trim();
  const session = await api("/api/sessions", {
    method: "POST",
    body: JSON.stringify({ label }),
  });
  el.sessionLabel.value = "";
  await loadSessions();
  await selectSession(session.id);
}

async function cloneCurrentSession() {
  if (!state.currentSessionId || !state.currentSession) return;
  const suggested = `${state.currentSession.label} copy`;
  const label = window.prompt("Clone session as:", suggested);
  if (label === null) return;
  const session = await api(`/api/sessions/${state.currentSessionId}/clone`, {
    method: "POST",
    body: JSON.stringify({ label }),
  });
  await loadSessions();
  await selectSession(session.id);
}

function attachCommandForms() {
  document.querySelectorAll(".command-form").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const command = form.dataset.command;
      const args = serializeForm(form);
      try {
        await runCommand(command, args);
      } catch (error) {
        renderTask({
          command,
          status: "failed",
          logs: [String(error.message || error)],
        });
      }
    });
  });

  document.querySelectorAll("button[data-command]").forEach((button) => {
    button.addEventListener("click", async () => {
      const command = button.dataset.command;
      if (["test", "vast-cleanup", "vast-sync"].includes(command)) {
        try {
          await runCommand(command);
        } catch (error) {
          renderTask({ command, status: "failed", logs: [String(error.message || error)] });
        }
      }
    });
  });

  document.querySelectorAll(".upload-form").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const command = form.dataset.command;
      const fileInput = form.querySelector('input[type="file"]');
      const file = fileInput?.files?.[0];
      if (!file) {
        renderTask({ command, status: "failed", logs: ["Choose a hit file first."] });
        return;
      }
      const content = await file.text();
      const args = {
        content,
        source_name: file.name,
      };
      if (form.dataset.round) {
        args.round = form.dataset.round;
      }
      try {
        await runCommand(command, args);
        form.reset();
      } catch (error) {
        renderTask({ command, status: "failed", logs: [String(error.message || error)] });
      }
    });
  });
}

async function init() {
  attachCommandForms();
  el.sessionForm.addEventListener("submit", createSession);
  el.refreshSessions.addEventListener("click", () => loadSessions().catch(console.error));
  el.cloneSession.addEventListener("click", () => cloneCurrentSession().catch(console.error));
  startRefreshLoop();
  await loadSessions();
}

init().catch((error) => {
  console.error(error);
  el.taskLog.textContent = String(error.message || error);
});
