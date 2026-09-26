// Sensible defaults for the console's choosers.

/** Projects by name, and the one to open on: the one with the most datasets. */
export function projectChoice(projects, datasets = []) {
  const sorted = [...projects].sort((a, b) => a.name.localeCompare(b.name));
  const counts = new Map();
  for (const dataset of datasets) counts.set(dataset.project_id, (counts.get(dataset.project_id) || 0) + 1);
  const busiest = sorted.reduce((best, project) => ((counts.get(project.id) || 0) > (counts.get(best?.id) || 0) ? project : best), sorted[0] ?? null);
  return { projects: sorted, preferred: busiest?.id ?? null };
}
