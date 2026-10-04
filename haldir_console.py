"""A window onto what is on this machine, and what is governed.

`haldir top` is the terminal console for agents that are *already* governed.
This is the counterpart for the other question — "what do I even have?" — and
it is a window rather than a table because the answer is not uniform:
configured MCP servers, running processes, and governed agents are three
different kinds of thing with three different next steps.

Two rules shaped the code:

* **The data shaping is a pure function.** `build_rows()` turns a discovery
  payload and a register payload into rows; the Tk code renders rows. The part
  with the logic is tested without a display, and the part with the display
  has almost no logic to get wrong.
* **It does not start anything.** Discovering is reading. Enrolling a server
  means copying a config snippet, which the window offers and never applies —
  a console that silently rewrites your MCP config is not a console anyone
  should run twice.

Stdlib only (`tkinter` ships with CPython): a tool whose job is to tell you
what you already have should not need installing first.
"""

from __future__ import annotations

from typing import Any, Callable

#: The MCP entry that points a client at Haldir — the on-ramp this console
#: exists to offer. Remote first, because it is one line and no install.
HALDIR_MCP_SNIPPET = (
    '{"mcpServers": {"haldir": {"type": "http", "url": "https://haldir.xyz/mcp"}}}'
)

_GROUPS = (
    "MCP clients",
    "MCP servers they launch",
    "Running now",
    "Governed by Haldir",
)


def build_rows(
    discovery: dict[str, Any] | None,
    register: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Flatten discovery + register into the rows the window shows.

    Each row: `group`, `name`, `kind`, `detail`, `suggestion`, `snippet`.
    Pure — no Tk, no I/O — so the interesting half of this module is testable
    on a machine with no display, which is every CI runner.
    """
    rows: list[dict[str, Any]] = []

    for client in (discovery or {}).get("clients", []):
        servers = client.get("servers") or {}
        detail = client.get("config_path", "")
        if not client.get("readable"):
            detail += f"  ·  {client.get('note') or 'unreadable'}"
        rows.append({
            "group":      "MCP clients",
            "name":       client.get("client", "?"),
            "kind":       "client",
            "detail":     detail,
            "suggestion": (
                "Add Haldir as a server in this client, and every tool call it "
                "makes through Haldir is scoped, capped and audited."
            ),
            "snippet":    HALDIR_MCP_SNIPPET,
        })
        for server_name, spec in servers.items():
            governed = "haldir" in str(spec).lower()
            rows.append({
                "group":      "MCP servers they launch",
                "name":       server_name,
                "kind":       "mcp-server",
                "detail":     f"{spec}  ·  via {client.get('client', '?')}",
                "suggestion": (
                    "Already routed through Haldir." if governed else
                    "Ungoverned: it runs with whatever credentials it has and "
                    "nothing records what it did. Route it through the Haldir "
                    "proxy, or register it as an upstream and govern it from "
                    "the Haldir side."
                ),
                "snippet":    "" if governed else HALDIR_MCP_SNIPPET,
            })

    for proc in (discovery or {}).get("processes", []):
        rows.append({
            "group":      "Running now",
            "name":       f"{proc.get('label', '?')} #{proc.get('pid', '?')}",
            "kind":       proc.get("kind", "process"),
            "detail":     proc.get("command", ""),
            "suggestion": (
                "This is a Haldir component." if proc.get("kind") == "governed" else
                "Running outside Haldir: no session, no spend cap, no audit "
                "trail for what it does."
            ),
            "snippet":    "",
        })

    for agent in (register or {}).get("agents", []):
        sessions = agent.get("sessions") or {}
        activity = agent.get("activity") or {}
        rows.append({
            "group":      "Governed by Haldir",
            "name":       agent.get("agent_id", "?"),
            "kind":       agent.get("kind", "agent"),
            "detail": (
                f"{', '.join(agent.get('default_scopes') or []) or 'no scopes'} · "
                f"{sessions.get('total', 0)} sessions · "
                f"${activity.get('cost_usd', 0.0):.6f} logged · "
                f"{activity.get('flagged', 0)} flagged"
            ),
            "suggestion": (
                "Discoverable — a capability card is published."
                if agent.get("card_id") else
                "Not discoverable. `haldir publish` lists it in the public index."
            ),
            "snippet":    "",
        })

    rows.sort(key=lambda r: (_GROUPS.index(r["group"]) if r["group"] in _GROUPS else 99,
                             r["name"].lower()))
    return rows


def summarize(discovery: dict[str, Any] | None,
              register: dict[str, Any] | None = None) -> str:
    """The one-line status under the title."""
    d = (discovery or {}).get("summary") or {}
    parts = [
        f"{d.get('clients', 0)} clients",
        f"{d.get('configured_servers', 0)} configured servers",
        f"{d.get('processes', 0)} running",
    ]
    if register:
        s = register.get("summary") or {}
        parts.append(f"{s.get('agents', 0)} governed agents")
    return " · ".join(parts)


def render_rows_text(rows: list[dict[str, Any]]) -> str:
    """The same rows as a terminal listing — what `--json`'s human sibling
    prints, and what the window falls back to when there is no display."""
    out: list[str] = []
    current = ""
    for row in rows:
        if row["group"] != current:
            current = row["group"]
            out.append("")
            out.append(current.upper())
        out.append(f"  {row['name']}  [{row['kind']}]")
        if row["detail"]:
            out.append(f"      {row['detail']}")
    return "\n".join(out).strip("\n")


def open_console(
    rows: list[dict[str, Any]],
    summary: str = "",
    on_refresh: Callable[[], list[dict[str, Any]]] | None = None,
) -> None:
    """Open the window. Raises `RuntimeError` when there is no display.

    Deliberately thin: it renders rows and hands refresh back to the caller.
    Everything worth testing happens in `build_rows`.
    """
    import tkinter as tk
    from tkinter import ttk

    # Palette from the landing page and the dashboards — the console is the
    # same product seen from the operator's desktop.
    BG, FG, DIM, GOLD, PANEL = "#0b0b0b", "#e0ddd5", "#8a857c", "#b8973a", "#131313"

    try:
        root = tk.Tk()
    except tk.TclError as err:  # no DISPLAY, no X, a bare container
        raise RuntimeError(
            "no display available — run `haldir discover` for the same "
            f"information in the terminal ({err})"
        ) from err

    root.title("Haldir console")
    root.configure(bg=BG)
    root.geometry("900x560")

    header = tk.Frame(root, bg=BG)
    header.pack(fill="x", padx=12, pady=(10, 4))
    tk.Label(header, text="Haldir console", bg=BG, fg=FG,
             font=("TkDefaultFont", 14, "bold")).pack(side="left")
    status = tk.Label(header, text=summary, bg=BG, fg=DIM)
    status.pack(side="left", padx=12)

    body = tk.Frame(root, bg=BG)
    body.pack(fill="both", expand=True, padx=12, pady=6)

    # ttk widgets ignore the Tk background palette — without this the tree
    # renders in the system's light theme next to a dark frame.
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                    foreground=FG, borderwidth=0, rowheight=22)
    style.configure("Treeview.Heading", background=BG, foreground=GOLD,
                    relief="flat")
    style.map("Treeview", background=[("selected", "#2a2418")],
              foreground=[("selected", FG)])

    detail = tk.Text(body, width=40, bg=PANEL, fg=FG, wrap="word",
                     relief="flat", padx=10, pady=10,
                     font=("TkDefaultFont", 9))
    detail.pack(side="right", fill="y", padx=(10, 0))
    detail.configure(state="disabled")

    columns = ("kind", "detail")
    tree = ttk.Treeview(body, columns=columns, show="tree headings", height=16)
    tree.heading("#0", text="name")
    tree.heading("kind", text="kind")
    tree.heading("detail", text="detail")
    tree.column("#0", width=230, anchor="w")
    tree.column("kind", width=90, anchor="w")
    tree.column("detail", width=280, anchor="w")
    tree.pack(side="left", fill="both", expand=True)

    def fill(tree_rows: list[dict[str, Any]]) -> None:
        tree.delete(*tree.get_children())
        nodes: dict[str, str] = {}
        for row in tree_rows:
            group = row["group"]
            if group not in nodes:
                nodes[group] = tree.insert("", "end", text=group, open=True)
            tree.insert(nodes[group], "end", text=row["name"],
                        values=(row["kind"], row["detail"]), tags=(row["group"],))
        for iid in tree.get_children():
            tree.item(iid, open=True)

    def index_rows(tree_rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        """Map a tree item to its row, in insertion order."""
        out: dict[str, dict[str, Any]] = {}
        pending = list(tree_rows)
        for group_item in tree.get_children():
            for child in tree.get_children(group_item):
                if pending:
                    out[child] = pending.pop(0)
        return out

    rows_by_item: dict[str, dict[str, Any]] = {}

    def refresh() -> None:
        nonlocal rows_by_item
        current = on_refresh() if on_refresh else rows
        fill(current)
        rows_by_item = index_rows(current)

    def show_selected(_event: Any = None) -> None:
        selection = tree.selection()
        detail.configure(state="normal")
        detail.delete("1.0", "end")
        if selection and selection[0] in rows_by_item:
            row = rows_by_item[selection[0]]
            detail.insert("end", f"{row['name']}\n\n", ("name",))
            detail.insert("end", f"{row['detail']}\n\n")
            if row["suggestion"]:
                detail.insert("end", f"{row['suggestion']}\n\n")
            if row["snippet"]:
                detail.insert("end", "Config to paste:\n")
                detail.insert("end", row["snippet"] + "\n")
        detail.tag_configure("name", foreground=GOLD)
        detail.configure(state="disabled")

    tree.bind("<<TreeviewSelect>>", show_selected)

    buttons = tk.Frame(root, bg=BG)
    buttons.pack(fill="x", padx=12, pady=(0, 10))

    def copy_snippet() -> None:
        selection = tree.selection()
        row = rows_by_item.get(selection[0]) if selection else None
        if row and row["snippet"]:
            root.clipboard_clear()
            root.clipboard_append(row["snippet"])
            status.configure(text="copied the Haldir config snippet")

    # tk.Button ignores the background on several Linux themes, which is how a
    # dark console ends up with white buttons. ttk takes the style above.
    style.configure("Console.TButton", background=PANEL, foreground=FG,
                    borderwidth=0, focusthickness=0, padding=(12, 6))
    style.configure("Accent.TButton", background=PANEL, foreground=GOLD,
                    borderwidth=0, focusthickness=0, padding=(12, 6))
    style.map("Console.TButton", background=[("active", "#1e1e1e")])
    style.map("Accent.TButton", background=[("active", "#1e1e1e")])
    ttk.Button(buttons, text="Refresh", style="Console.TButton",
               command=refresh).pack(side="left")
    ttk.Button(buttons, text="Copy Haldir config", style="Accent.TButton",
               command=copy_snippet).pack(side="left", padx=8)
    ttk.Button(buttons, text="Close", style="Console.TButton",
               command=root.destroy).pack(side="right")

    refresh()
    # Select something before showing: the detail pane is where the "what do I
    # do about this" lives, and an empty pane on launch reads as a broken one.
    first_children = tree.get_children()
    if first_children:
        grandchildren = tree.get_children(first_children[0])
        if grandchildren:
            tree.selection_set(grandchildren[0])
            tree.focus(grandchildren[0])
    root.mainloop()
