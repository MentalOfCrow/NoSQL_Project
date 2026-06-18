const graphElement = document.querySelector("#graph");
const graphStatus = document.querySelector("#graph-status");
const seedButton = document.querySelector("#seed-button");
const pathsElement = document.querySelector("#paths");
const vulnerabilitiesElement = document.querySelector("#vulnerabilities");
const resourcesElement = document.querySelector("#resources");
const statsElement = document.querySelector("#stats");
const servicesElement = document.querySelector("#services");
const identityRisksElement = document.querySelector("#identity-risks");
const recommendationsElement = document.querySelector("#recommendations");

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
  const nodes = payload.nodes.map((node) => {
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

  const edges = payload.relationships.map((relationship) => ({
    id: relationship.id,
    from: relationship.source,
    to: relationship.target,
    label: relationship.type,
    arrows: "to",
    font: { size: 10, align: "middle" },
    color: "#8b97aa",
  }));

  new vis.Network(
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
  const [graph, stats, paths, shortestPaths, vulnerableMachines, resources, services, identityRisks, recommendations] = await Promise.all([
    api("/api/graph"),
    api("/api/stats"),
    api("/api/attack-paths"),
    api("/api/shortest-paths"),
    api("/api/vulnerable-machines"),
    api("/api/resources"),
    api("/api/exposed-services"),
    api("/api/identity-risks"),
    api("/api/recommendations"),
  ]);

  renderGraph(graph);
  renderStats(stats);
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

seedButton.addEventListener("click", async () => {
  seedButton.disabled = true;
  seedButton.textContent = "Chargement...";
  graphStatus.textContent = "Creation du graphe";
  try {
    await api("/api/seed", { method: "POST" });
    await loadDashboard();
    seedButton.textContent = "Graphe charge";
  } catch (error) {
    graphStatus.textContent = error.message;
    seedButton.textContent = "Reessayer";
  } finally {
    seedButton.disabled = false;
  }
});

loadDashboard().catch((error) => {
  graphStatus.textContent = error.message;
  renderList(pathsElement, [], "Graphe non charge", () => null);
  renderList(vulnerabilitiesElement, [], "Graphe non charge", () => null);
  renderList(resourcesElement, [], "Graphe non charge", () => null);
  renderList(servicesElement, [], "Graphe non charge", () => null);
  renderList(identityRisksElement, [], "Graphe non charge", () => null);
  renderList(recommendationsElement, [], "Graphe non charge", () => null);
});
