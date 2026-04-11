const state = {
  sessions: [],
  currentSessionId: null,
  currentSession: null,
  activeTaskId: null,
  pollHandle: null,
};

const el = {
  sessionForm: document.querySelector("#sessionForm"),
  sessionLabel: document.querySelector("#sessionLabel"),
  sessionList: document.querySelector("#sessionList"),
  refreshSessions: document.querySelector("#refreshSessions"),
  sessionTitle: document.querySelector("#sessionTitle"),
  sessionUpdated: document.querySelector("#sessionUpdated"),
  sessionWorkspace: document.querySelector("#sessionWorkspace"),
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

function formatDate(value) {
  if (!value) return "unknown";
  return new Date(value).toLocaleString();
}

function classForStatus(status) {
  if (status === "running") return "running";
  if (status === "completed") return "completed";
  if (status === "failed") return "failed";
  return "muted";
}

function renderSessions() {
  if (!state.sessions.length) {
    el.sessionList.innerHTML = `<div class="artifact-empty">No sessions yet.</div>`;
    return;
  }

  el.sessionList.innerHTML = state.sessions
    .map(
      (session) => `
        <button class="session-item ${session.id === state.currentSessionId ? "active" : ""}" data-session-id="${session.id}">
          <strong>${session.label}</strong>
          <small>${session.artifacts.length} artifacts · updated ${formatDate(session.updated_at)}</small>
        </button>
      `
    )
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
    `<span class="chip mono">${task.id}</span>`,
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
          <span>${key.replaceAll("_", " ")}</span>
          <span>${Array.isArray(value) ? value.join(", ") : value}</span>
        </div>
      `
    )
    .join("");
}

function renderArtifacts(artifacts) {
  if (!artifacts?.length) {
    el.artifactGrid.innerHTML = `<div class="artifact-empty">No artifacts yet.</div>`;
    return;
  }

  el.artifactGrid.innerHTML = artifacts
    .map((artifact) => {
      const summary = summarizeObject(artifact.summary);
      const content =
        artifact.kind === "json"
          ? JSON.stringify(artifact.data, null, 2)
          : artifact.content || "";
      return `
        <article class="artifact-card">
          <h4>${artifact.name}</h4>
          <p class="artifact-meta">${artifact.kind} · ${artifact.size} bytes · ${formatDate(artifact.updated_at)}</p>
          ${summary ? `<div class="artifact-summary">${summary}</div>` : ""}
          ${
            content
              ? `<pre class="artifact-content">${content.replace(/[&<>]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[char]))}</pre>`
              : ""
          }
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
    el.sessionTitle.textContent = "No session selected";
    el.sessionUpdated.textContent = "Idle";
    el.sessionUpdated.className = "chip muted";
    el.sessionWorkspace.textContent = "No workspace";
    el.emptyState.classList.remove("hidden");
    el.commandDeck.classList.add("hidden");
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
  renderArtifacts(session.artifacts);

  const latestTask = session.tasks?.[0] || null;
  renderTask(latestTask);
  if (latestTask && latestTask.status === "running") {
    state.activeTaskId = latestTask.id;
    startPolling(latestTask.id);
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
  renderSessions();
  if (payload.status !== "running") {
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

  document.querySelectorAll("[data-command='test']").forEach((button) => {
    button.addEventListener("click", async () => {
      try {
        await runCommand("test");
      } catch (error) {
        renderTask({ command: "test", status: "failed", logs: [String(error.message || error)] });
      }
    });
  });
}

async function init() {
  attachCommandForms();
  el.sessionForm.addEventListener("submit", createSession);
  el.refreshSessions.addEventListener("click", () => loadSessions().catch(console.error));
  await loadSessions();
}

init().catch((error) => {
  console.error(error);
  el.taskLog.textContent = String(error.message || error);
});
