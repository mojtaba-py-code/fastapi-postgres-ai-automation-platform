// Projects: the containers for datasets, sources, workflows and reports.

import { button, confirmDialog, field, form, h, input, notify, pageHeader, pagedTable, section, badge, textarea, time } from "../ui.js";
import { href } from "../router.js";

export function projectsPage(app) {
  const writable = app.can("projects:write");
  const list = pagedTable(
    [
      { title: "Project", render: (row) => h("div", {}, h("a", { href: href("/datasets", { project: row.id }) }, row.name), row.description && h("p", { class: "muted small" }, row.description)) },
      { title: "Status", render: (row) => badge(row.status) },
      { title: "Created", render: (row) => time(row.created_at) },
      writable && {
        title: "",
        class: "actions",
        render: (row) =>
          button(
            "Delete",
            async () => {
              const confirmed = await confirmDialog({
                title: `Delete ${row.name}?`,
                message: "A project can be deleted only once its datasets are gone. This cannot be undone.",
                confirmLabel: "Delete the project",
                danger: true,
              });
              if (!confirmed) return;
              await app.api.delete(`/projects/${row.id}`);
              notify(`${row.name} was deleted.`, { kind: "success" });
              app.refresh();
            },
            { kind: "ghost" },
          ),
      },
    ].filter(Boolean),
    (cursor) => app.api.get("/projects", { limit: 50, cursor }),
    { empty: "No projects yet." },
  );

  return h(
    "div",
    { class: "stack" },
    pageHeader("Projects", { description: "Group the datasets, sources, workflows and reports of one line of work." }),
    writable &&
      section(
        "New project",
        {},
        form(
          {
            submitLabel: "Create the project",
            onSubmit: async ({ name, description }) => {
              const project = await app.api.post("/projects", { name: name.trim(), description: description.trim() || null });
              notify(`${project.name} was created.`, { kind: "success" });
              app.refresh();
            },
            className: "form-inline",
          },
          field("Name", input({ name: "name", required: true, maxlength: "200" })),
          field("Description", textarea({ name: "description", rows: 2, maxlength: "2000" }), { hint: "Optional." }),
        ),
      ),
    section("All projects", {}, list),
  );
}
