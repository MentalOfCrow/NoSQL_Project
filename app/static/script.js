const graphElement = document.querySelector("#graph");
const graphStatus = document.querySelector("#graph-status");
const seedButton = document.querySelector("#seed-button");
const exportButton = document.querySelector("#export-button");
const applySegmentationButton = document.querySelector("#apply-segmentation-button");
const resetSegmentationButton = document.querySelector("#reset-segmentation-button");
const pathsElement = document.querySelector("#paths");
const vulnerabilitiesElement = document.querySelector("#vulnerabilities");
const resourcesElement = document.querySelector("#resources");
const statsElement = document.querySelector("#stats");
const servicesElement = document.querySelector("#services");
const identityRisksElement = document.querySelector("#identity-risks");
const recommendationsElement = document.querySelector("#recommendations");
const queryCatalogElement = document.querySelector("#query-catalog");
const queryResultsElement = document.querySelector("#query-results");
const segmentationElement = document.querySelector("#segmentation");
const diagnosticsElement = document.querySelector("#diagnostics");
const segmentationStateElement = document.querySelector("#segmentation-state");
const executiveSummaryElement = document.querySelector("#executive-summary");
const riskMatrixElement = document.querySelector("#risk-matrix");
const deliverablesElement = document.querySelector("#deliverables");
const graphFiltersElement = document.querySelector("#graph-filters");

let fullGraphPayload = { nodes: [], relationships: [] };
let visibleLabels = new Set();
let network = null;

const colors = {
  User: "#2563eb",
  Machine: "#dc2626",
  Service: "#15803d",
  Vulnerability: "#b45309",
  Group: "#7c3aed",
  Resource: "#0f766e",
};

async function api(path, options = {}) {
  const response = await fetch(path, options);
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.detail || "Erreur API");
  }
  return response.json();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function nodeLabel(node) {
  return node.properties.name || node.properties.cve || `node-${node.id}`;
}

function renderGraph(payload) {
  fullGraphPayload = payload;
  if (!visibleLabels.size) {
    visibleLabels = new Set([...new Set(payload.nodes.map((node) => node.labels[0] || "Node"))]);
  }
  renderGraphFilters(payload);
  const visibleNodeIds = new Set(
    payload.nodes
      .filter((node) => visibleLabels.has(node.labels[0] || "Node"))
      .map((node) => node.id),
  );
  const nodes = payload.nodes.filter((node) => visibleNodeIds.has(node.id)).map((node) => {
    const label = node.labels[0] || "Node";
    return {
      id: node.id,
      label: nodeLabel(node),
      title: `${label}\n${JSON.stringify(node.properties, null, 2)}`,
      color: colors[label] || "#647085",
      shape: label === "Machine" ? "box" : "dot",
      font: { color: "#18202f" },
    };
  });

  const edges = payload.relationships
    .filter((relationship) => visibleNodeIds.has(relationship.source) && visibleNodeIds.has(relationship.target))
    .map((relationship) => ({
      id: relationship.id,
      from: relationship.source,
      to: relationship.target,
      label: relationship.type,
      arrows: "to",
      font: { size: 10, align: "middle" },
      color: "#8b97aa",
    }));

  network = new vis.Network(
    graphElement,
    { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) },
    {
      layout: { improvedLayout: true },
      physics: { stabilization: true, barnesHut: { springLength: 150 } },
      interaction: { hover: true },
    },
  );

  graphStatus.textContent = `${nodes.length} noeuds, ${edges.length} relations`;
}

function renderGraphFilters(payload) {
  const labels = [...new Set(payload.nodes.map((node) => node.labels[0] || "Node"))].sort();
  graphFiltersElement.replaceChildren();
  labels.forEach((label) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = visibleLabels.has(label) ? "filter active" : "filter";
    button.textContent = label;
    button.addEventListener("click", () => {
      if (visibleLabels.has(label)) {
        visibleLabels.delete(label);
      } else {
        visibleLabels.add(label);
      }
      renderGraph(fullGraphPayload);
    });
    graphFiltersElement.appendChild(button);
  });
}

function item(title, meta, level = "") {
  const article = document.createElement("article");
  article.className = "item";
  article.innerHTML = `<strong class="${level}">${title}</strong><div class="meta">${meta}</div>`;
  return article;
}

function renderList(element, rows, emptyText, builder) {
  element.replaceChildren();
  if (!rows.length) {
    element.appendChild(item(emptyText, "Clique sur Charger le graphe si les donnees ne sont pas encore creees."));
    return;
  }
  rows.forEach((row, index) => element.appendChild(builder(row, index)));
}

async function loadDashboard() {
  const [
    graph,
    stats,
    paths,
    shortestPaths,
    vulnerableMachines,
    resources,
    services,
    identityRisks,
    recommendations,
    executiveSummary,
    riskMatrix,
    queryCatalog,
    queryResults,
    segmentation,
    segmentationState,
    deliverables,
    diagnostics,
  ] = await Promise.all([
    api("/api/graph"),
    api("/api/stats"),
    api("/api/attack-paths"),
    api("/api/shortest-paths"),
    api("/api/vulnerable-machines"),
    api("/api/resources"),
    api("/api/exposed-services"),
    api("/api/identity-risks"),
    api("/api/recommendations"),
    api("/api/executive-summary"),
    api("/api/risk-matrix"),
    api("/api/query-catalog"),
    api("/api/query-results"),
    api("/api/segmentation-plan"),
    api("/api/segmentation-state"),
    api("/api/deliverables"),
    api("/api/diagnostics"),
  ]);

  renderExecutiveSummary(executiveSummary);
  renderGraph(graph);
  renderStats(stats);
  renderDiagnostics(diagnostics);
  renderList(pathsElement, paths.paths, "Aucun chemin trouve", (row) =>
    item(
      `${escapeHtml(row.target)} <span class="badge">${escapeHtml(row.criticality)}</span>`,
      `Chemin: ${escapeHtml(row.nodes.join(" -> "))}<br>Nombre de sauts: ${row.hops}`,
      row.criticality,
    ),
  );

  shortestPaths.paths.forEach((row) => {
    pathsElement.appendChild(
      item(
        `Plus court chemin vers ${escapeHtml(row.target)}`,
        `${escapeHtml(row.nodes.join(" -> "))}<br>${row.hops} saut(s)`,
        row.criticality,
      ),
    );
  });

  renderList(vulnerabilitiesElement, vulnerableMachines.machines, "Aucune machine vulnerable trouvee", (row) =>
    item(
      `${escapeHtml(row.machine)} - ${escapeHtml(row.cve)}`,
      `${escapeHtml(row.vulnerability)}, score ${row.score}<br>Chemin: ${escapeHtml(row.path.join(" -> "))}`,
      row.score >= 9 ? "critical" : "high",
    ),
  );

  renderList(resourcesElement, resources.resources, "Aucune ressource accessible trouvee", (row) =>
    item(
      `${escapeHtml(row.resource)} <span class="badge">${escapeHtml(row.sensitivity)}</span>`,
      `Hebergee sur ${escapeHtml(row.machine)}<br>Chemin: ${escapeHtml(row.path.join(" -> "))}`,
      row.sensitivity === "critical" ? "critical" : "high",
    ),
  );

  renderList(servicesElement, services.services, "Aucun service expose trouve", (row) =>
    item(
      `${escapeHtml(row.machine)}:${row.port}`,
      `${escapeHtml(row.service)} - criticite machine: ${escapeHtml(row.criticality)}<br>Vulnerabilites liees: ${escapeHtml(row.cves.filter(Boolean).join(", ") || "aucune")}`,
      row.criticality === "critical" ? "critical" : "",
    ),
  );

  const identityRows = [
    ...identityRisks.adminRights.map((row) => ({ ...row, type: "Admin direct" })),
    ...identityRisks.groupRisks.map((row) => ({ ...row, type: `Groupe ${row.group}` })),
  ];
  renderList(identityRisksElement, identityRows, "Aucun risque d'identite trouve", (row) =>
    item(
      `${escapeHtml(row.user)} - ${escapeHtml(row.type)}`,
      `${escapeHtml(row.role)} vers ${escapeHtml(row.machine)} (${escapeHtml(row.criticality)})`,
      row.criticality === "critical" ? "critical" : "high",
    ),
  );

  renderList(recommendationsElement, recommendations.recommendations, "Aucune recommandation", (text, index) =>
    item(`Mesure ${index + 1}`, escapeHtml(text)),
  );

  renderQueryCatalog(queryCatalog.queries);
  renderQueryResults(queryResults.results);
  renderSegmentation(segmentation);
  renderSegmentationState(segmentationState);
  renderRiskMatrix(riskMatrix.machines);
  renderDeliverables(deliverables.items);
}

async function bootstrapAndLoad() {
  graphStatus.textContent = "Connexion a Neo4j";
  try {
    const result = await api("/api/bootstrap", { method: "POST" });
    graphStatus.textContent = result.loaded ? "Graphe charge automatiquement" : "Graphe deja charge";
    await loadDashboard();
  } catch (error) {
    graphStatus.textContent = error.message;
    renderEmptyState(error.message);
  }
}

function renderStats(stats) {
  const cards = [
    { label: "Noeuds", value: stats.totalNodes },
    { label: "Relations", value: stats.totalRelationships },
    ...stats.nodes.map((row) => ({ label: row.label, value: row.total })),
  ];
  statsElement.replaceChildren();
  cards.forEach((card) => {
    const div = document.createElement("div");
    div.className = "stat";
    div.innerHTML = `<strong>${card.value}</strong><span>${escapeHtml(card.label)}</span>`;
    statsElement.appendChild(div);
  });
}

function renderDiagnostics(diagnostics) {
  diagnosticsElement.innerHTML = `
    <span class="${diagnostics.ready ? "ok" : "warning"}">${diagnostics.ready ? "Pret" : "Vide"}</span>
    <span>Neo4j: ${escapeHtml(diagnostics.uri)}</span>
    <span>Noeuds: ${diagnostics.counts.nodes}</span>
    <span>Relations: ${diagnostics.counts.relationships}</span>
  `;
}

function renderExecutiveSummary(summary) {
  const cards = [
    ["Machine compromise", summary.compromisedMachine],
    ["Chemin principal", summary.mainAttackPath],
    ["Actifs critiques", summary.criticalAssets.join(", ")],
    ["Statut", summary.status],
  ];
  executiveSummaryElement.replaceChildren();
  cards.forEach(([title, value]) => {
    const card = document.createElement("article");
    card.className = "summary-card";
    card.innerHTML = `<span>${escapeHtml(title)}</span><strong>${escapeHtml(value)}</strong>`;
    executiveSummaryElement.appendChild(card);
  });
  const riskCard = document.createElement("article");
  riskCard.className = "summary-card summary-card-wide";
  riskCard.innerHTML = `<span>Risques principaux</span><ul>${summary.mainRisks
    .map((risk) => `<li>${escapeHtml(risk)}</li>`)
    .join("")}</ul>`;
  executiveSummaryElement.appendChild(riskCard);
}

function renderRiskMatrix(machines) {
  riskMatrixElement.replaceChildren();
  machines.forEach((machine) => {
    const card = document.createElement("article");
    card.className = `risk-card ${machine.criticality}`;
    card.innerHTML = `
      <div class="risk-score">${machine.riskScore}</div>
      <strong>${escapeHtml(machine.machine)}</strong>
      <span>${escapeHtml(machine.type)} - ${escapeHtml(machine.criticality)}</span>
      <p>Vulnerabilites: ${machine.vulnerabilityCount} | Score max: ${machine.maxVulnerabilityScore}</p>
      <p>Services: ${escapeHtml(machine.services.filter(Boolean).join(", ") || "aucun")}</p>
      <p>Ressources: ${escapeHtml(machine.resources.filter(Boolean).join(", ") || "aucune")}</p>
    `;
    riskMatrixElement.appendChild(card);
  });
}

function renderDeliverables(items) {
  deliverablesElement.replaceChildren();
  items.forEach((entry) => {
    const card = document.createElement("article");
    card.className = "deliverable";
    card.innerHTML = `
      <strong>${escapeHtml(entry.name)}</strong>
      <span>${escapeHtml(entry.status)}</span>
      <code>${escapeHtml(entry.file)}</code>
    `;
    deliverablesElement.appendChild(card);
  });
}

function renderQueryCatalog(queries) {
  queryCatalogElement.replaceChildren();
  queries.forEach((query) => {
    const article = document.createElement("article");
    article.className = "query-card";
    article.innerHTML = `
      <strong>${escapeHtml(query.title)}</strong>
      <pre><code>${escapeHtml(query.query)}</code></pre>
      <button class="copy-query" type="button" data-query="${escapeHtml(query.query)}">Copier la requete</button>
      <p>${escapeHtml(query.comment)}</p>
    `;
    queryCatalogElement.appendChild(article);
  });
  queryCatalogElement.querySelectorAll(".copy-query").forEach((button) => {
    button.addEventListener("click", async () => {
      await navigator.clipboard.writeText(button.dataset.query);
      button.textContent = "Copie";
      setTimeout(() => {
        button.textContent = "Copier la requete";
      }, 1200);
    });
  });
}

function renderQueryResults(results) {
  queryResultsElement.replaceChildren();
  results.forEach((result) => {
    const article = document.createElement("article");
    article.className = "query-card";
    const rows = result.rows.slice(0, 8).map((row) => `<li>${escapeHtml(JSON.stringify(row))}</li>`).join("");
    article.innerHTML = `
      <strong>${escapeHtml(result.title)}</strong>
      <p>${escapeHtml(result.comment)}</p>
      <ul>${rows || "<li>Aucun resultat</li>"}</ul>
    `;
    queryResultsElement.appendChild(article);
  });
}

function renderSegmentation(segmentation) {
  const columns = [
    ["Avant", segmentation.before],
    ["Actions", segmentation.actions],
    ["Apres", segmentation.after],
  ];
  segmentationElement.replaceChildren();
  columns.forEach(([title, rows]) => {
    const article = document.createElement("article");
    article.className = "query-card";
    article.innerHTML = `
      <strong>${escapeHtml(title)}</strong>
      <ul>${rows.map((row) => `<li>${escapeHtml(row)}</li>`).join("")}</ul>
    `;
    segmentationElement.appendChild(article);
  });
}

function renderSegmentationState(state) {
  const status = state.mode === "segmented" ? "Segmentation appliquee" : "Graphe initial";
  const statusClass = state.mode === "segmented" ? "ok" : "warning";
  segmentationStateElement.innerHTML = `
    <span class="${statusClass}">${escapeHtml(status)}</span>
    <span>Chemins critiques restants: ${state.criticalPathCount}</span>
    <span>Flux controles: ${state.restrictedFlows.length}</span>
  `;
}

async function exportDashboard() {
  const payload = await api("/api/export");
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "cybercorp-analysis-export.json";
  link.click();
  URL.revokeObjectURL(url);
}

seedButton.addEventListener("click", async () => {
  seedButton.disabled = true;
  seedButton.textContent = "Rechargement...";
  graphStatus.textContent = "Recreation du graphe";
  try {
    await api("/api/seed", { method: "POST" });
    await loadDashboard();
    seedButton.textContent = "Graphe recharge";
  } catch (error) {
    graphStatus.textContent = error.message;
    seedButton.textContent = "Reessayer";
  } finally {
    seedButton.disabled = false;
  }
});

exportButton.addEventListener("click", () => {
  exportDashboard().catch((error) => {
    graphStatus.textContent = error.message;
  });
});

async function runSegmentationAction(button, action, loadingText, doneText) {
  button.disabled = true;
  const previousText = button.textContent;
  button.textContent = loadingText;
  graphStatus.textContent = loadingText;
  try {
    await api(action, { method: "POST" });
    await loadDashboard();
    button.textContent = doneText;
    setTimeout(() => {
      button.textContent = previousText;
    }, 1400);
  } catch (error) {
    graphStatus.textContent = error.message;
    button.textContent = previousText;
  } finally {
    button.disabled = false;
  }
}

applySegmentationButton.addEventListener("click", () => {
  runSegmentationAction(
    applySegmentationButton,
    "/api/segmentation/apply",
    "Application segmentation...",
    "Segmentation appliquee",
  );
});

resetSegmentationButton.addEventListener("click", () => {
  runSegmentationAction(
    resetSegmentationButton,
    "/api/segmentation/reset",
    "Restauration...",
    "Graphe restaure",
  );
});

function renderEmptyState(message = "Graphe non charge") {
  statsElement.replaceChildren();
  diagnosticsElement.innerHTML = `<span class="warning">Base non chargee</span>`;
  graphElement.replaceChildren();
  graphStatus.textContent = message;
  renderList(pathsElement, [], "Graphe non charge", () => null);
  renderList(vulnerabilitiesElement, [], "Graphe non charge", () => null);
  renderList(resourcesElement, [], "Graphe non charge", () => null);
  renderList(servicesElement, [], "Graphe non charge", () => null);
  renderList(identityRisksElement, [], "Graphe non charge", () => null);
  renderList(recommendationsElement, [], "Graphe non charge", () => null);
  queryCatalogElement.replaceChildren();
  queryResultsElement.replaceChildren();
  segmentationElement.replaceChildren();
  segmentationStateElement.replaceChildren();
  executiveSummaryElement.replaceChildren();
  riskMatrixElement.replaceChildren();
  deliverablesElement.replaceChildren();
  graphFiltersElement.replaceChildren();
}

bootstrapAndLoad();
