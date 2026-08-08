#!/usr/bin/env python3
"""
hoard-gui: a window for the hoard vault.

All crypto is imported from hoard.py. Nothing here derives a key, chooses a
nonce, or touches a cipher.

Deliberately plain. It uses the system GTK theme instead of shipping its own
colours, so it looks like the rest of your desktop rather than like a brand.
"""

from __future__ import annotations

import copy
import hashlib
import os
import platform
import sys
import threading
import time
from pathlib import Path

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
from gi.repository import Gdk, GLib, Gtk, Pango  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hoard  # noqa: E402

AUTOLOCK_SECONDS = 300

# The only styling worth overriding. Secrets are monospace so that l, 1, I and
# 0, O cannot be confused; everything else inherits the system theme.
CSS = b"""
.secret { font-family: monospace; }
.fieldlabel { font-size: 11px; opacity: 0.65; }
.timestamps { font-size: 11px; opacity: 0.6; }
.sectionhead { font-size: 11px; opacity: 0.65; }
.statusbar { font-size: 11px; opacity: 0.75; padding: 3px 8px; }
.error { color: #cc4444; }
"""


def icon_button(icon: str, tooltip: str, fallback: str) -> Gtk.Button:
    """Icon button, degrading to a text label if the theme lacks the icon."""
    btn = Gtk.Button()
    theme = Gtk.IconTheme.get_default()
    if theme.has_icon(icon):
        btn.set_image(Gtk.Image.new_from_icon_name(icon, Gtk.IconSize.MENU))
        btn.set_relief(Gtk.ReliefStyle.NONE)
    else:
        btn.set_label(fallback)
    btn.set_tooltip_text(tooltip)
    return btn


def run_off_main(work, on_done, on_error, dispatch) -> threading.Thread:
    """
    Run work() on a worker thread and hand the outcome to dispatch().

    Nothing inside work() may touch a widget or read window state. GTK is not
    thread safe, so results come back through dispatch, which is GLib.idle_add
    in the application and a synchronous stub in the tests.

    Returns the thread so tests can join it. The application ignores it.
    """
    def worker() -> None:
        try:
            result = work()
        except Exception as exc:
            dispatch(on_error, exc)
        else:
            dispatch(on_done, result)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return thread


class Log:
    """
    Recent activity, shown in the status bar.

    Entry names appear on your own screen because that is useful. They are
    replaced with a short hash in the exported diagnostics, since the list of
    sites you hold accounts on does not belong in a bug report.
    """

    def __init__(self) -> None:
        self.lines: list[tuple[str, str, str | None]] = []

    def add(self, message: str, name: str | None = None) -> None:
        self.lines.append((time.strftime("%H:%M:%S"), message, name))

    def latest(self) -> str:
        if not self.lines:
            return "Ready"
        ts, msg, name = self.lines[-1]
        return f"{ts}  {msg}" + (f": {name}" if name else "")

    def diagnostics(self, vault: Path) -> str:
        from shutil import which
        out = [
            "hoard diagnostics",
            f"generated     {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"python        {platform.python_version()}",
            f"platform      {platform.platform()}",
            f"gtk           {Gtk.get_major_version()}.{Gtk.get_minor_version()}.{Gtk.get_micro_version()}",
            f"session       {os.environ.get('XDG_SESSION_TYPE', 'unknown')}",
            f"desktop       {os.environ.get('XDG_CURRENT_DESKTOP', 'unknown')}",
            f"gtk theme     {Gtk.Settings.get_default().get_property('gtk-theme-name')}",
            f"clipboard     wl-copy={bool(which('wl-copy'))} xclip={bool(which('xclip'))}",
            f"vault exists  {vault.exists()}",
            f"vault size    {vault.stat().st_size if vault.exists() else 0} bytes",
            f"argon2id      m={hoard.ARGON['m']}KiB t={hoard.ARGON['t']} p={hoard.ARGON['p']}",
            "",
            "recent activity (entry names redacted)",
        ]
        for ts, msg, name in self.lines[-40:]:
            tag = "  item:" + hashlib.sha256(name.encode()).hexdigest()[:6] if name else ""
            out.append(f"  {ts}  {msg}{tag}")
        return "\n".join(out)


class HoardWindow(Gtk.Window):
    def __init__(self, vault_path: Path) -> None:
        super().__init__(title="hoard")
        self.vault_path = vault_path
        self.password: str | None = None
        self.vault: dict | None = None
        self.selected: str | None = None
        self.revealed = False
        self.log = Log()
        self._autolock: int | None = None
        # Bumped on every lock. A result whose generation no longer matches
        # arrived after the vault closed and must not repaint the window.
        self._generation = 0
        self._busy = False

        self.set_default_size(900, 580)
        self.set_position(Gtk.WindowPosition.CENTER)
        self.connect("destroy", Gtk.main_quit)
        self.connect("key-press-event", self.on_key)

        self.stack = Gtk.Stack()
        self.add(self.stack)
        self.stack.add_named(self.build_lock(), "lock")
        self.stack.add_named(self.build_main(), "vault")
        self.stack.set_visible_child_name("lock")

    # ------------------------------------------------------------ lock view

    def build_lock(self) -> Gtk.Widget:
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        form = Gtk.Grid(row_spacing=8, column_spacing=10)
        form.set_halign(Gtk.Align.CENTER)
        form.set_valign(Gtk.Align.CENTER)

        heading = Gtk.Label()
        heading.set_markup("<big><b>Unlock vault</b></big>")
        heading.set_halign(Gtk.Align.START)
        form.attach(heading, 0, 0, 2, 1)

        path = Gtk.Label(label=str(self.vault_path), xalign=0)
        path.get_style_context().add_class("fieldlabel")
        path.set_margin_bottom(10)
        form.attach(path, 0, 1, 2, 1)

        label = Gtk.Label(label="Master password", xalign=0)
        form.attach(label, 0, 2, 1, 1)

        self.pw_entry = Gtk.Entry()
        self.pw_entry.set_visibility(False)
        self.pw_entry.set_width_chars(30)
        self.pw_entry.set_activates_default(True)
        self.pw_entry.connect("activate", lambda *_: self.unlock())
        form.attach(self.pw_entry, 1, 2, 1, 1)

        self.unlock_btn = Gtk.Button(label="Unlock")
        self.unlock_btn.get_style_context().add_class("suggested-action")
        self.unlock_btn.set_halign(Gtk.Align.END)
        self.unlock_btn.connect("clicked", lambda *_: self.unlock())
        form.attach(self.unlock_btn, 1, 3, 1, 1)

        self.lock_error = Gtk.Label(label="", xalign=0)
        self.lock_error.get_style_context().add_class("error")
        form.attach(self.lock_error, 0, 4, 2, 1)

        outer.pack_start(form, True, True, 0)
        return outer

    # ------------------------------------------------------------ main view

    def build_menubar(self) -> Gtk.MenuBar:
        bar = Gtk.MenuBar()

        def menu(title: str, items) -> None:
            root = Gtk.MenuItem(label=title)
            sub = Gtk.Menu()
            for entry in items:
                if entry is None:
                    sub.append(Gtk.SeparatorMenuItem())
                    continue
                label, handler = entry
                mi = Gtk.MenuItem(label=label)
                mi.connect("activate", lambda _w, h=handler: h())
                sub.append(mi)
            root.set_submenu(sub)
            bar.append(root)

        menu("File", [
            ("Lock vault", lambda: self.lock("Locked")),
            None,
            ("Quit", Gtk.main_quit),
        ])
        menu("Edit", [
            ("Copy password", lambda: self.selected and self.copy_password(self.selected)),
            ("Copy username", lambda: self.selected and self.copy_field(self.selected, "username")),
            None,
            ("Find", lambda: self.search.grab_focus()),
        ])
        menu("Vault", [
            ("Add item", self.add_item_dialog),
            ("Delete item", lambda: self.selected and self.delete_item(self.selected)),
            None,
            ("Change master password", self.change_master_dialog),
        ])
        menu("Help", [
            ("Copy diagnostics", self.copy_diagnostics),
            ("About", self.about_dialog),
        ])
        return bar

    def build_main(self) -> Gtk.Widget:
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        root.pack_start(self.build_menubar(), False, False, 0)

        search_row = Gtk.Box()
        search_row.set_border_width(6)
        self.search = Gtk.SearchEntry()
        self.search.set_placeholder_text("Search vault")
        self.search.connect("search-changed", lambda *_: self.refresh_list())
        self.search.set_halign(Gtk.Align.CENTER)
        self.search.set_width_chars(46)
        search_row.pack_start(self.search, True, False, 0)
        root.pack_start(search_row, False, False, 0)
        root.pack_start(Gtk.Separator(), False, False, 0)

        panes = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)

        # Sidebar. Only real controls live here. When there is one kind of
        # item and no folders, a Types section would be furniture.
        sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        sidebar.set_size_request(150, -1)
        self.sidebar_list = Gtk.ListBox()
        self.sidebar_list.connect(
            "row-activated", lambda *_: (self.search.set_text(""), self.search.grab_focus())
        )
        row = Gtk.ListBoxRow()
        row_box = Gtk.Box(spacing=6)
        row_box.set_border_width(8)
        row_box.pack_start(Gtk.Label(label="All items", xalign=0), True, True, 0)
        self.sidebar_count = Gtk.Label(label="0")
        self.sidebar_count.get_style_context().add_class("fieldlabel")
        row_box.pack_end(self.sidebar_count, False, False, 0)
        row.add(row_box)
        self.sidebar_list.add(row)
        self.sidebar_list.select_row(row)
        sidebar.pack_start(self.sidebar_list, False, False, 0)
        panes.pack_start(sidebar, False, False, 0)
        panes.pack_start(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL), False, False, 0)

        # item list
        list_col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        list_col.set_size_request(240, -1)
        self.listbox = Gtk.ListBox()
        self.listbox.connect("row-selected", self.on_row_selected)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.add(self.listbox)
        list_col.pack_start(scroll, True, True, 0)

        add_bar = Gtk.Box()
        add_bar.set_border_width(6)
        add_btn = Gtk.Button(label="+")
        add_btn.set_tooltip_text("Add item")
        add_btn.connect("clicked", lambda *_: self.add_item_dialog())
        add_bar.pack_start(add_btn, True, True, 0)
        list_col.pack_start(add_bar, False, False, 0)
        panes.pack_start(list_col, False, False, 0)
        panes.pack_start(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL), False, False, 0)

        # detail
        self.detail = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.detail.set_border_width(12)
        detail_scroll = Gtk.ScrolledWindow()
        detail_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        detail_scroll.add(self.detail)
        panes.pack_start(detail_scroll, True, True, 0)

        root.pack_start(panes, True, True, 0)
        root.pack_start(Gtk.Separator(), False, False, 0)

        status = Gtk.Box()
        status.get_style_context().add_class("statusbar")
        self.status_label = Gtk.Label(label="Ready", xalign=0)
        self.status_label.set_ellipsize(Pango.EllipsizeMode.END)
        status.pack_start(self.status_label, True, True, 0)
        diag = Gtk.Button(label="Copy diagnostics")
        diag.set_relief(Gtk.ReliefStyle.NONE)
        diag.connect("clicked", lambda *_: self.copy_diagnostics())
        status.pack_end(diag, False, False, 0)
        root.pack_start(status, False, False, 0)
        return root

    # -------------------------------------------------------------- helpers

    def note(self, message: str, name: str | None = None) -> None:
        self.log.add(message, name)
        if hasattr(self, "status_label"):
            self.status_label.set_text(self.log.latest())

    def entries(self) -> dict:
        return (self.vault or {}).get("entries", {})

    def _set_busy(self, busy: bool, button: Gtk.Button | None = None,
                  label: str | None = None) -> None:
        """
        Mark an operation in flight, and optionally disable the control that
        started it.

        The button is optional because only unlock has one that outlives the
        operation. The dialogs destroy themselves before the write finishes and
        the Delete button is rebuilt by refresh_list, so for those there would
        be nothing left to re-enable and the busy flag alone stops a second
        operation starting.

        No spinner: these take a quarter second, and something that appears and
        vanishes that fast reads as a glitch rather than as progress.
        """
        self._busy = busy
        if button is not None:
            button.set_sensitive(not busy)
            if label is not None:
                button.set_label(label)

    def unlock(self) -> None:
        if self._busy:
            return
        pw = self.pw_entry.get_text()
        if not pw:
            self.lock_error.set_text("Enter your master password.")
            return

        # Captured before the thread starts. Reading self from a worker means
        # racing autolock, which sets password to None underneath it.
        path, generation = self.vault_path, self._generation
        self.lock_error.set_text("")
        self._set_busy(True, self.unlock_btn, "Unlocking")

        def done(vault: dict) -> None:
            self._set_busy(False, self.unlock_btn, "Unlock")
            if generation != self._generation:
                return
            self.vault = vault
            self.password = pw
            self.pw_entry.set_text("")
            self.note("Vault unlocked")
            self.refresh_list()
            self.stack.set_visible_child_name("vault")
            self.reset_autolock()

        def failed(exc: Exception) -> None:
            self._set_busy(False, self.unlock_btn, "Unlock")
            if generation != self._generation:
                return
            message = str(exc)
            self.lock_error.set_text(message[0].upper() + message[1:] + ".")
            self.log.add("Unlock failed")

        run_off_main(lambda: hoard.read_vault(path, pw), done, failed, GLib.idle_add)

    def lock(self, why: str = "Locked") -> None:
        self._generation += 1
        self.password = None
        self.vault = None
        self.selected = None
        self.revealed = False
        for child in self.detail.get_children():
            self.detail.remove(child)
        self.log.add(why)
        self.stack.set_visible_child_name("lock")
        self.pw_entry.grab_focus()
        if self._autolock:
            GLib.source_remove(self._autolock)
            self._autolock = None

    def reset_autolock(self) -> None:
        if self._autolock:
            GLib.source_remove(self._autolock)
        self._autolock = GLib.timeout_add_seconds(
            AUTOLOCK_SECONDS,
            lambda: (self.lock("Locked automatically after 5 minutes idle"), False)[1],
        )

    def refresh_list(self) -> None:
        for child in self.listbox.get_children():
            self.listbox.remove(child)
        needle = self.search.get_text().lower()
        names = sorted(n for n in self.entries() if needle in n.lower())
        if hasattr(self, "sidebar_count"):
            self.sidebar_count.set_text(str(len(self.entries())))

        if not names:
            row = Gtk.ListBoxRow()
            row.set_selectable(False)
            msg = "No items yet. Use + to add one." if not self.entries() else "No matches."
            lbl = Gtk.Label(label=msg, xalign=0)
            lbl.get_style_context().add_class("fieldlabel")
            lbl.set_line_wrap(True)
            lbl.set_margin_top(10)
            lbl.set_margin_start(10)
            lbl.set_margin_end(10)
            row.add(lbl)
            self.listbox.add(row)

        for name in names:
            row = Gtk.ListBoxRow()
            row.name_value = name  # type: ignore[attr-defined]
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
            box.set_border_width(7)
            title = Gtk.Label(label=name, xalign=0)
            title.set_ellipsize(Pango.EllipsizeMode.END)
            box.pack_start(title, False, False, 0)
            user = self.entries()[name].get("username") or ""
            if user:
                sub = Gtk.Label(label=user, xalign=0)
                sub.get_style_context().add_class("fieldlabel")
                sub.set_ellipsize(Pango.EllipsizeMode.END)
                box.pack_start(sub, False, False, 0)
            row.add(box)
            self.listbox.add(row)
        self.listbox.show_all()

    def on_row_selected(self, _box, row) -> None:
        if row is None or not hasattr(row, "name_value"):
            return
        self.selected = row.name_value  # type: ignore[attr-defined]
        self.revealed = False
        self.show_detail(self.selected)
        self.reset_autolock()

    # --------------------------------------------------------------- detail

    def show_detail(self, name: str) -> None:
        for child in self.detail.get_children():
            self.detail.remove(child)
        entry = self.entries().get(name)
        if entry is None:
            return

        head = Gtk.Label(label="ITEM INFORMATION", xalign=0)
        head.get_style_context().add_class("sectionhead")
        head.set_margin_bottom(10)
        self.detail.pack_start(head, False, False, 0)

        self.field("Name", name)
        self.field("Username", entry.get("username") or "", copyable="username")
        self.password_field(name)
        self.field("Website", entry.get("url") or "", copyable="url")
        if entry.get("note"):
            self.field("Note", entry["note"])

        if entry.get("updated"):
            stamp = time.strftime("%d %b %Y, %H:%M:%S", time.localtime(entry["updated"]))
            lbl = Gtk.Label(label=f"Updated: {stamp}", xalign=0)
            lbl.get_style_context().add_class("timestamps")
            lbl.set_margin_top(14)
            self.detail.pack_start(lbl, False, False, 0)

        actions = Gtk.Box(spacing=6)
        actions.set_margin_top(16)
        delete = Gtk.Button(label="Delete")
        delete.get_style_context().add_class("destructive-action")
        delete.connect("clicked", lambda *_: self.delete_item(name))
        actions.pack_end(delete, False, False, 0)
        self.detail.pack_start(actions, False, False, 0)

        self.detail.show_all()

    def field(self, label: str, value: str, copyable: str | None = None) -> None:
        lbl = Gtk.Label(label=label, xalign=0)
        lbl.get_style_context().add_class("fieldlabel")
        self.detail.pack_start(lbl, False, False, 0)

        row = Gtk.Box(spacing=6)
        row.set_margin_bottom(12)
        val = Gtk.Label(label=value or "Not set", xalign=0)
        # Selectable so you can drag-copy it, but never focusable: a focused
        # selectable label draws a caret and then looks like a field you can
        # type into, which is a lie.
        val.set_selectable(bool(value))
        val.set_can_focus(False)
        val.set_line_wrap(True)
        val.set_ellipsize(Pango.EllipsizeMode.END)
        row.pack_start(val, True, True, 0)
        if copyable and value:
            btn = icon_button("edit-copy", f"Copy {label.lower()}", "Copy")
            btn.connect("clicked", lambda *_: self.copy_field(self.selected, copyable))
            row.pack_end(btn, False, False, 0)
        self.detail.pack_start(row, False, False, 0)

    def password_field(self, name: str) -> None:
        lbl = Gtk.Label(label="Password", xalign=0)
        lbl.get_style_context().add_class("fieldlabel")
        self.detail.pack_start(lbl, False, False, 0)

        row = Gtk.Box(spacing=6)
        row.set_margin_bottom(12)
        self.secret_label = Gtk.Label(label="•" * 12, xalign=0)
        self.secret_label.get_style_context().add_class("secret")
        self.secret_label.set_selectable(True)
        self.secret_label.set_can_focus(False)
        self.secret_label.set_ellipsize(Pango.EllipsizeMode.END)
        row.pack_start(self.secret_label, True, True, 0)

        eye = icon_button("view-reveal-symbolic", "Show password", "Show")
        eye.connect("clicked", lambda b: self.toggle_reveal(b, name))
        row.pack_end(eye, False, False, 0)

        copy = icon_button("edit-copy", "Copy password", "Copy")
        copy.connect("clicked", lambda *_: self.copy_password(name))
        row.pack_end(copy, False, False, 0)

        self.detail.pack_start(row, False, False, 0)

    def toggle_reveal(self, button: Gtk.Button, name: str) -> None:
        self.revealed = not self.revealed
        if self.revealed:
            self.secret_label.set_text(self.entries()[name]["password"])
            button.set_tooltip_text("Hide password")
            self.note("Password shown on screen", name)
        else:
            self.secret_label.set_text("•" * 12)
            button.set_tooltip_text("Show password")
            self.note("Password hidden", name)
        self.reset_autolock()

    # -------------------------------------------------------------- actions

    def copy_password(self, name: str) -> None:
        secret = self.entries()[name]["password"]
        if hoard.clipboard_copy(secret):
            self.note(f"Password copied, clipboard clears in {hoard.CLIP_SECONDS}s", name)
        else:
            Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text(secret, -1)
            self.note("Password copied. It will not clear automatically.", name)
        self.reset_autolock()

    def copy_field(self, name: str | None, key: str) -> None:
        if not name:
            return
        value = self.entries()[name].get(key) or ""
        if not value:
            return
        Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text(value, -1)
        self.note(f"{key.capitalize()} copied", name)
        self.reset_autolock()

    def save(self, vault: dict, password: str, on_saved) -> None:
        """
        Write the vault off the main thread, then hand the caller the state to
        commit.

        The caller passes the vault it intends rather than mutating self.vault
        and hoping. A failed write used to leave memory and disk disagreeing
        with nothing saying so, and going async would have widened that window
        from a quarter second to however long the worker takes.

        No button is disabled here. Every caller destroys its dialog before the
        write finishes, so there would be nothing left to re-enable; the busy
        flag is what stops a second write starting.
        """
        if self._busy:
            return
        path, generation = self.vault_path, self._generation
        self._set_busy(True)

        def done(_result) -> None:
            self._set_busy(False)
            if generation != self._generation:
                return
            self.vault = vault
            self.password = password
            on_saved()

        def failed(exc: Exception) -> None:
            self._set_busy(False)
            if generation != self._generation:
                return
            self.note(f"Could not save: {exc}")

        run_off_main(lambda: hoard.write_vault(path, vault, password), done, failed,
                     GLib.idle_add)

    def add_item_dialog(self) -> None:
        dlg = Gtk.Dialog(title="Add item", transient_for=self, modal=True)
        dlg.add_button("Cancel", Gtk.ResponseType.CANCEL)
        save = dlg.add_button("Save", Gtk.ResponseType.OK)
        save.get_style_context().add_class("suggested-action")

        grid = Gtk.Grid(row_spacing=8, column_spacing=10)
        grid.set_border_width(14)
        fields = {}
        for i, (key, label) in enumerate((("name", "Name"), ("username", "Username"), ("url", "Website"))):
            grid.attach(Gtk.Label(label=label, xalign=0), 0, i, 1, 1)
            e = Gtk.Entry()
            e.set_width_chars(32)
            fields[key] = e
            grid.attach(e, 1, i, 1, 1)

        grid.attach(Gtk.Label(label="Password", xalign=0), 0, 3, 1, 1)
        pw_box = Gtk.Box(spacing=6)
        pw = Gtk.Entry()
        pw.set_visibility(False)
        pw.set_width_chars(24)
        pw_box.pack_start(pw, True, True, 0)
        gen = Gtk.Button(label="Generate")
        gen.connect("clicked", lambda *_: (pw.set_text(hoard.generate(24)), pw.set_visibility(True)))
        pw_box.pack_end(gen, False, False, 0)
        grid.attach(pw_box, 1, 3, 1, 1)

        err = Gtk.Label(label="", xalign=0)
        err.get_style_context().add_class("error")
        grid.attach(err, 0, 4, 2, 1)

        dlg.get_content_area().add(grid)
        dlg.show_all()

        while True:
            if dlg.run() != Gtk.ResponseType.OK:
                break
            name = fields["name"].get_text().strip()
            secret = pw.get_text()
            if not name:
                err.set_text("Give the item a name.")
                continue
            if name in self.entries():
                err.set_text(f"An item called {name} already exists.")
                continue
            if not secret:
                err.set_text("Enter a password, or press Generate.")
                continue
            updated = copy.deepcopy(self.vault)
            updated.setdefault("entries", {})[name] = {
                "password": secret,
                "username": fields["username"].get_text().strip(),
                "url": fields["url"].get_text().strip(),
                "note": "",
                "updated": int(time.time()),
            }
            self.save(updated, self.password,
                      lambda: (self.note("Item saved", name), self.refresh_list()))
            break
        dlg.destroy()
        self.reset_autolock()

    def delete_item(self, name: str) -> None:
        dlg = Gtk.MessageDialog(
            transient_for=self, modal=True,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.OK_CANCEL,
            text=f"Delete {name}?",
        )
        dlg.format_secondary_text("The password is gone once the vault is written.")
        response = dlg.run()
        dlg.destroy()
        if response != Gtk.ResponseType.OK:
            return
        updated = copy.deepcopy(self.vault)
        del updated["entries"][name]

        def after() -> None:
            self.note("Item deleted", name)
            self.selected = None
            for child in self.detail.get_children():
                self.detail.remove(child)
            self.refresh_list()

        self.save(updated, self.password, after)

    def change_master_dialog(self) -> None:
        dlg = Gtk.Dialog(title="Change master password", transient_for=self, modal=True)
        dlg.add_button("Cancel", Gtk.ResponseType.CANCEL)
        ok = dlg.add_button("Change", Gtk.ResponseType.OK)
        ok.get_style_context().add_class("suggested-action")
        grid = Gtk.Grid(row_spacing=8, column_spacing=10)
        grid.set_border_width(14)
        first, second = Gtk.Entry(), Gtk.Entry()
        for i, (label, widget) in enumerate((("New password", first), ("Repeat", second))):
            widget.set_visibility(False)
            widget.set_width_chars(30)
            grid.attach(Gtk.Label(label=label, xalign=0), 0, i, 1, 1)
            grid.attach(widget, 1, i, 1, 1)
        err = Gtk.Label(label="", xalign=0)
        err.get_style_context().add_class("error")
        grid.attach(err, 0, 2, 2, 1)
        dlg.get_content_area().add(grid)
        dlg.show_all()

        while True:
            if dlg.run() != Gtk.ResponseType.OK:
                break
            if not first.get_text():
                err.set_text("Enter a password.")
                continue
            if first.get_text() != second.get_text():
                err.set_text("Those do not match.")
                continue
            # Assigned by save() on success only. It used to be set before the
            # write, so a failure left the window believing a change that had
            # never reached the file.
            self.save(self.vault, first.get_text(),
                      lambda: self.note("Master password changed, vault re-encrypted"))
            break
        dlg.destroy()
        self.reset_autolock()

    def copy_diagnostics(self) -> None:
        Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text(
            self.log.diagnostics(self.vault_path), -1
        )
        self.note("Diagnostics copied. Item names are redacted.")

    def about_dialog(self) -> None:
        dlg = Gtk.MessageDialog(
            transient_for=self, modal=True,
            message_type=Gtk.MessageType.INFO,
            buttons=Gtk.ButtonsType.OK,
            text="hoard",
        )
        dlg.format_secondary_text(
            "An encrypted password vault in one readable file.\n\n"
            f"Argon2id (m={hoard.ARGON['m']} KiB, t={hoard.ARGON['t']}, p={hoard.ARGON['p']}) "
            "and ChaCha20-Poly1305.\n"
            "Unaudited. Do not trust it with anything you cannot afford to lose."
        )
        dlg.run()
        dlg.destroy()

    def on_key(self, _widget, event) -> bool:
        ctrl = event.state & Gdk.ModifierType.CONTROL_MASK
        key = Gdk.keyval_name(event.keyval)
        in_vault = self.stack.get_visible_child_name() == "vault"
        if ctrl and key == "l":
            self.lock("Locked")
            return True
        if ctrl and key == "q":
            Gtk.main_quit()
            return True
        if in_vault and ctrl and key == "f":
            self.search.grab_focus()
            return True
        if in_vault and ctrl and key == "c" and self.selected:
            self.copy_password(self.selected)
            return True
        if in_vault and key == "Escape":
            self.lock("Locked")
            return True
        return False


def main() -> int:
    vault_path = Path(sys.argv[1]) if len(sys.argv) > 1 else hoard.DEFAULT_VAULT
    if not vault_path.exists():
        print(f"No vault at {vault_path}", file=sys.stderr)
        print("Create one first:  ./hoard.py init", file=sys.stderr)
        return 1

    provider = Gtk.CssProvider()
    provider.load_from_data(CSS)
    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
    )

    win = HoardWindow(vault_path)
    win.show_all()
    win.pw_entry.grab_focus()
    Gtk.main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
