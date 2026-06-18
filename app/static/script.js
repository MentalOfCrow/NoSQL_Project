const graphElement = document.querySelector("#graph");
const graphStatus = document.querySelector("#graph-status");
const seedButton = document.querySelector("#seed-button");
const pathsElement = document.querySelector("#paths");
const vulnerabilitiesElement = document.querySelector("#vulnerabilities");
const resourcesElement = document.querySelector("#resources");

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
  rows.forEach((row) => element.appendChild(builder(row)));
}

async function loadDashboard() {
  const [graph, paths, vulnerableMachines, resources] = await Promise.all([
    api("/api/graph"),
    api("/api/attack-paths"),
    api("/api/vulnerable-machines"),
    api("/api/resources"),
  ]);

  renderGraph(graph);
  renderList(pathsElement, paths.paths, "Aucun chemin trouve", (row) =>
    item(
      `${row.target} <span class="badge">${row.criticality}</span>`,
      `Chemin: ${row.nodes.join(" -> ")}<br>Nombre de sauts: ${row.hops}`,
      row.criticality,
    ),
  );

  renderList(vulnerabilitiesElement, vulnerableMachines.machines, "Aucune machine vulnerable trouvee", (row) =>
    item(
      `${row.machine} - ${row.cve}`,
      `${row.vulnerability}, score ${row.score}<br>Chemin: ${row.path.join(" -> ")}`,
      row.score >= 9 ? "critical" : "high",
    ),
  );

  renderList(resourcesElement, resources.resources, "Aucune ressource accessible trouvee", (row) =>
    item(
      `${row.resource} <span class="badge">${row.sensitivity}</span>`,
      `Hebergee sur ${row.machine}<br>Chemin: ${row.path.join(" -> ")}`,
      row.sensitivity === "critical" ? "critical" : "high",
    ),
  );
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
});
