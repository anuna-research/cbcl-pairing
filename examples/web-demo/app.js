const elements = {
  start: document.querySelector("#start"),
  reset: document.querySelector("#reset"),
  approve: document.querySelector("#approve"),
  decline: document.querySelector("#decline"),
  busy: document.querySelector("#busy"),
  headline: document.querySelector("#headline"),
  allocatorState: document.querySelector("#allocator-state"),
  claimantState: document.querySelector("#claimant-state"),
  carrier: document.querySelector("#carrier"),
  intent: document.querySelector("#intent"),
  decisionControls: document.querySelector("#decision-controls"),
  relayFrames: document.querySelector("#relay-frames"),
  relayBytes: document.querySelector("#relay-bytes"),
  relaySees: document.querySelector("#relay-sees"),
  relayCannotSee: document.querySelector("#relay-cannot-see"),
  relayNote: document.querySelector("#relay-note"),
  phases: Array.from(document.querySelectorAll("#ceremony-phases li")),
  timeline: document.querySelector("#timeline"),
  outcome: document.querySelector("#outcome"),
};

async function request(path) {
  setBusy(true, "Running protocol…");
  let errorMessage = "";
  try {
    const response = await fetch(path, { method: "POST" });
    const state = await response.json();
    if (!response.ok) {
      throw new Error(state.error || `Request failed (${response.status})`);
    }
    render(state);
  } catch (error) {
    errorMessage = error.message;
  } finally {
    setBusy(false);
    if (errorMessage) {
      elements.busy.textContent = errorMessage;
      elements.busy.classList.add("error");
    }
  }
}

function setBusy(busy, message = "") {
  document.body.classList.toggle("is-busy", busy);
  elements.start.disabled = busy;
  elements.reset.disabled = busy;
  elements.approve.disabled = busy;
  elements.decline.disabled = busy;
  elements.busy.classList.remove("error");
  elements.busy.textContent = busy ? message : "";
}

function render(state) {
  elements.headline.textContent = state.headline;
  elements.relayFrames.textContent = state.relay.frames;
  elements.relayBytes.textContent = Number(state.relay.opaqueBytes).toLocaleString();
  elements.relaySees.replaceChildren(...listItems(state.relay.sees));
  elements.relayCannotSee.replaceChildren(...listItems(state.relay.cannotSee));
  elements.relayNote.textContent = state.relay.note;

  renderCarrier(state.carrier);
  renderIntent(state.intent);
  renderPhases(state.stage);
  renderTimeline(state.timeline);
  renderOutcome(state.outcome);

  const awaiting = state.stage === "awaiting-decision";
  elements.decisionControls.hidden = !awaiting;
  elements.allocatorState.textContent = allocatorLabel(state.stage);
  elements.claimantState.textContent = claimantLabel(state.stage);
  elements.start.textContent = state.stage === "idle" ? "Create invitation" : "Start fresh";
}

function renderCarrier(carrier) {
  if (!carrier) {
    elements.carrier.className = "empty";
    elements.carrier.textContent = "No invitation yet.";
    return;
  }
  const words = carrier.words.map((word) => `<span>${escapeHtml(word)}</span>`).join("");
  elements.carrier.className = "carrier";
  elements.carrier.innerHTML = `
    <p class="carrier-label">Two-word invitation · ${carrier.entropyBits} bits</p>
    <div class="words">${words}</div>
    <dl>
      <div><dt>Nameplate</dt><dd>${escapeHtml(carrier.nameplate)}</dd></div>
      <div><dt>Relay</dt><dd>${escapeHtml(carrier.relay)}</dd></div>
    </dl>
    <p class="fine-print">${escapeHtml(carrier.note)}</p>
  `;
}

function renderIntent(intent) {
  if (!intent) {
    elements.intent.className = "empty";
    elements.intent.textContent = "Authenticated intent will appear here.";
    return;
  }
  const fields = intent.fields.map((field) => `
    <div>
      <dt>${escapeHtml(field.label)}</dt>
      <dd>${escapeHtml(field.value)}</dd>
    </div>
  `).join("");
  elements.intent.className = "intent";
  elements.intent.innerHTML = `
    <p class="intent-action">${escapeHtml(intent.action)}</p>
    <h3>${escapeHtml(intent.authoritySummary)}</h3>
    <dl>${fields}</dl>
    <p class="claim-note">Claims are authenticated to the invitation holder, not independently vouched for by the relay.</p>
  `;
}

function renderTimeline(timeline) {
  if (!timeline.length) {
    elements.timeline.innerHTML = '<li class="empty-row">Create an invitation to begin.</li>';
    return;
  }
  elements.timeline.innerHTML = timeline.map((event, index) => {
    const direction = event.from === "Allocator" ? "forward" : "reverse";
    return `
    <li class="message-step ${direction}">
      <div class="message-meta">
        <span class="step">${String(index + 1).padStart(2, "0")}</span>
        <div>
          <strong>${escapeHtml(event.label)}</strong>
          <span>${escapeHtml(event.from)} → ${escapeHtml(event.to)}</span>
        </div>
      </div>
      <div class="message-route" role="img" aria-label="${escapeHtml(event.from)} sends ${escapeHtml(event.label)} through the blind relay to ${escapeHtml(event.to)}">
        <span class="route-node allocator-node" aria-hidden="true">A</span>
        <span class="route-segment" aria-hidden="true"></span>
        <span class="route-node relay-node" aria-hidden="true"><b>R</b></span>
        <span class="route-segment" aria-hidden="true"></span>
        <span class="route-node claimant-node" aria-hidden="true">C</span>
        <span class="moving-packet" aria-hidden="true"></span>
      </div>
      <div class="relay-readout">
        <strong>${Number(event.bytes).toLocaleString()} B</strong>
        <span>opaque · meaning hidden</span>
      </div>
    </li>
  `;
  }).join("");
}

function renderPhases(stage) {
  const states = phaseStates(stage);
  elements.phases.forEach((phase) => {
    const state = states[phase.dataset.phase];
    phase.dataset.state = state;
    const status = phase.querySelector(".phase-status");
    status.textContent = phaseStatus(state);
    if (state === "current") {
      phase.setAttribute("aria-current", "step");
    } else {
      phase.removeAttribute("aria-current");
    }
  });
}

function phaseStates(stage) {
  if (stage === "awaiting-decision") {
    return {
      invitation: "complete",
      pake: "complete",
      finished: "complete",
      roles: "complete",
      intent: "complete",
      consent: "current",
      grant: "locked",
    };
  }
  if (stage === "grant-delivered") {
    return Object.fromEntries(elements.phases.map((phase) => [phase.dataset.phase, "complete"]));
  }
  if (stage === "declined") {
    return {
      invitation: "complete",
      pake: "complete",
      finished: "complete",
      roles: "complete",
      intent: "complete",
      consent: "declined",
      grant: "skipped",
    };
  }
  return {
    invitation: "current",
    pake: "locked",
    finished: "locked",
    roles: "locked",
    intent: "locked",
    consent: "locked",
    grant: "locked",
  };
}

function phaseStatus(state) {
  if (state === "complete") return "done";
  if (state === "declined") return "declined";
  if (state === "skipped") return "not released";
  return state;
}

function renderOutcome(outcome) {
  if (!outcome) {
    elements.outcome.hidden = true;
    elements.outcome.replaceChildren();
    return;
  }
  const approved = outcome.kind === "approved";
  elements.outcome.hidden = false;
  elements.outcome.className = `outcome ${approved ? "success" : "neutral"}`;
  elements.outcome.innerHTML = `
    <span class="outcome-mark">${approved ? "✓" : "×"}</span>
    <div>
      <p class="eyebrow">${approved ? "Grant delivered" : "No grant released"}</p>
      <h2>${escapeHtml(outcome.message)}</h2>
      ${approved ? `<p>${outcome.deliveredPayloads} payload · ${outcome.verifierCalls} verifier call · ${outcome.bodyBytes} recognised body bytes</p>` : ""}
      ${outcome.next ? `<p>${escapeHtml(outcome.next)}</p>` : ""}
    </div>
  `;
}

function listItems(items) {
  return items.map((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    return li;
  });
}

function allocatorLabel(stage) {
  if (stage === "idle") return "waiting";
  if (stage === "awaiting-decision") return "intent sent";
  if (stage === "grant-delivered") return "grant sent";
  return "closed";
}

function claimantLabel(stage) {
  if (stage === "idle") return "waiting";
  if (stage === "awaiting-decision") return "decision needed";
  if (stage === "grant-delivered") return "verified";
  return "declined";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

elements.start.addEventListener("click", () => request("/api/start"));
elements.reset.addEventListener("click", () => request("/api/reset"));
elements.approve.addEventListener("click", () => request("/api/approve"));
elements.decline.addEventListener("click", () => request("/api/decline"));

fetch("/api/state")
  .then((response) => response.json())
  .then(render)
  .catch((error) => {
    elements.busy.textContent = error.message;
    elements.busy.classList.add("error");
  });
