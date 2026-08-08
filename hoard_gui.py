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
            ("Edit item", lambda: self.selected and self.edit_item_dialog(self.selected)),
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

        title = Gtk.Label(xalign=0)
        title.set_markup(f"<big><b>{GLib.markup_escape_text(name)}</b></big>")
        title.set_ellipsize(Pango.EllipsizeMode.END)
        title.set_margin_bottom(12)
        self.detail.pack_start(title, False, False, 0)

        # Grouped rather than one flat stack. Chunking related fields is the
        # one genuinely good idea in how Proton Pass and Bitwarden lay an item
        # out: your eye learns where each group sits instead of rereading
        # labels. The frame is GTK's own, so this follows the desktop theme
        # rather than introducing a palette.
        self.card([
            lambda: self.field_row("Username", entry.get("username") or "",
                                   copyable="username"),
            lambda: self.password_row(name),
        ])

        if entry.get("url"):
            self.card([lambda: self.field_row("Website", entry["url"], copyable="url")])

        if entry.get("note"):
            self.card([lambda: self.field_row("Note", entry["note"], wrap=True)])

        if entry.get("totp"):
            # Carried in from an import. hoard cannot generate codes yet, and
            # saying so is better than showing a field that looks broken.
            self.card([lambda: self.field_row(
                "2FA secret (hoard cannot generate codes yet)", entry["totp"])])

        if entry.get("updated"):
            stamp = time.strftime("%d %b %Y, %H:%M:%S", time.localtime(entry["updated"]))
            lbl = Gtk.Label(label=f"Updated: {stamp}", xalign=0)
            lbl.get_style_context().add_class("timestamps")
            lbl.set_margin_top(14)
            self.detail.pack_start(lbl, False, False, 0)

        actions = Gtk.Box(spacing=6)
        actions.set_margin_top(16)
        edit = Gtk.Button(label="Edit")
        edit.connect("clicked", lambda *_: self.edit_item_dialog(name))
        actions.pack_start(edit, False, False, 0)
        delete = Gtk.Button(label="Delete")
        delete.get_style_context().add_class("destructive-action")
        delete.connect("clicked", lambda *_: self.delete_item(name))
        actions.pack_end(delete, False, False, 0)
        self.detail.pack_start(actions, False, False, 0)

        self.detail.show_all()

    def card(self, rows) -> None:
        """One framed group of related fields, separated by GTK's own rules."""
        frame = Gtk.Frame()
        frame.set_margin_bottom(12)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        frame.add(box)
        for index, build in enumerate(rows):
            if index:
                box.pack_start(Gtk.Separator(), False, False, 0)
            box.pack_start(build(), False, False, 0)
        self.detail.pack_start(frame, False, False, 0)

    def field_row(self, label: str, value: str, copyable: str | None = None,
                  wrap: bool = False, buttons: list | None = None) -> Gtk.Widget:
        """
        A dim caption above the value, actions on the right. Every row is the
        same shape so your eye lands in the same place each time.
        """
        row = Gtk.Box(spacing=8)
        row.set_border_width(9)

        stack = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        caption = Gtk.Label(label=label, xalign=0)
        caption.get_style_context().add_class("fieldlabel")
        stack.pack_start(caption, False, False, 0)

        val = Gtk.Label(label=value or "Not set", xalign=0)
        # Selectable so you can drag-copy it, but never focusable: a focused
        # selectable label draws a caret and then looks like a field you can
        # type into, which is a lie.
        val.set_selectable(bool(value))
        val.set_can_focus(False)
        if wrap:
            val.set_line_wrap(True)
        else:
            val.set_ellipsize(Pango.EllipsizeMode.END)
        stack.pack_start(val, False, False, 0)
        row.pack_start(stack, True, True, 0)

        for button in reversed(buttons or []):
            row.pack_end(button, False, False, 0)
        if copyable and value:
            btn = icon_button("edit-copy", f"Copy {label.lower()}", "Copy")
            btn.connect("clicked", lambda *_: self.copy_field(self.selected, copyable))
            row.pack_end(btn, False, False, 0)
        return row

    def password_row(self, name: str) -> Gtk.Widget:
        self.secret_label = Gtk.Label(label="\u2022" * 12, xalign=0)
        self.secret_label.get_style_context().add_class("secret")
        self.secret_label.set_selectable(True)
        self.secret_label.set_can_focus(False)
        self.secret_label.set_ellipsize(Pango.EllipsizeMode.END)

        eye = icon_button("view-reveal-symbolic", "Show password", "Show")
        eye.connect("clicked", lambda b: self.toggle_reveal(b, name))
        copy = icon_button("edit-copy", "Copy password", "Copy")
        copy.connect("clicked", lambda *_: self.copy_password(name))

        row = Gtk.Box(spacing=8)
        row.set_border_width(9)
        stack = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        caption = Gtk.Label(label="Password", xalign=0)
        caption.get_style_context().add_class("fieldlabel")
        stack.pack_start(caption, False, False, 0)
        stack.pack_start(self.secret_label, False, False, 0)
        row.pack_start(stack, True, True, 0)
        row.pack_end(copy, False, False, 0)
        row.pack_end(eye, False, False, 0)
        return row

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

    def generator_dialog(self, parent) -> str | None:
        """
        Two modes behind a stack switcher, with a live preview and the entropy
        stated in bits.

        Bits rather than a coloured strength bar, because a bar means whatever
        its author felt like and this number is a fact you can check.
        """
        dlg = Gtk.Dialog(title="Generate", transient_for=parent, modal=True)
        dlg.add_button("Cancel", Gtk.ResponseType.CANCEL)
        use = dlg.add_button("Use", Gtk.ResponseType.OK)
        use.get_style_context().add_class("suggested-action")

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        outer.set_border_width(14)

        preview = Gtk.Label(xalign=0)
        preview.get_style_context().add_class("secret")
        preview.set_selectable(True)
        preview.set_can_focus(False)
        preview.set_line_wrap(True)
        preview.set_width_chars(40)
        outer.pack_start(preview, False, False, 0)

        strength = Gtk.Label(xalign=0)
        strength.get_style_context().add_class("fieldlabel")
        outer.pack_start(strength, False, False, 0)

        stack = Gtk.Stack()
        switcher = Gtk.StackSwitcher(stack=stack)
        switcher.set_halign(Gtk.Align.CENTER)
        outer.pack_start(switcher, False, False, 0)
        outer.pack_start(stack, False, False, 0)

        # ---- random characters
        chars_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        length_row = Gtk.Box(spacing=8)
        length_row.pack_start(Gtk.Label(label="Length", xalign=0), False, False, 0)
        length = Gtk.Adjustment(value=24, lower=4, upper=128, step_increment=1, page_increment=8)
        length_row.pack_start(Gtk.SpinButton(adjustment=length, numeric=True), False, False, 0)
        length_scale = Gtk.Scale(orientation=Gtk.Orientation.HORIZONTAL, adjustment=length)
        length_scale.set_draw_value(False)
        length_row.pack_start(length_scale, True, True, 0)
        chars_page.pack_start(length_row, False, False, 0)

        toggles = {}
        for key, label in (("upper", "Capitals, A to Z"),
                           ("lower", "Letters, a to z"),
                           ("digits", "Numbers, 0 to 9"),
                           ("symbols", "Symbols")):
            check = Gtk.CheckButton(label=label)
            check.set_active(True)
            toggles[key] = check
            chars_page.pack_start(check, False, False, 0)
        ambiguous = Gtk.CheckButton(label="Avoid look-alikes, l I 1 O 0")
        chars_page.pack_start(ambiguous, False, False, 0)
        stack.add_titled(chars_page, "chars", "Password")

        # ---- passphrase
        words_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        words_row = Gtk.Box(spacing=8)
        words_row.pack_start(Gtk.Label(label="Words", xalign=0), False, False, 0)
        words = Gtk.Adjustment(value=6, lower=3, upper=12, step_increment=1, page_increment=1)
        words_row.pack_start(Gtk.SpinButton(adjustment=words, numeric=True), False, False, 0)
        words_scale = Gtk.Scale(orientation=Gtk.Orientation.HORIZONTAL, adjustment=words)
        words_scale.set_draw_value(False)
        words_row.pack_start(words_scale, True, True, 0)
        words_page.pack_start(words_row, False, False, 0)

        sep_row = Gtk.Box(spacing=8)
        sep_row.pack_start(Gtk.Label(label="Between words", xalign=0), False, False, 0)
        separator = Gtk.ComboBoxText()
        for value, label in (("-", "hyphen"), (".", "full stop"), (" ", "space"), ("_", "underscore")):
            separator.append(value, label)
        separator.set_active_id("-")
        sep_row.pack_start(separator, False, False, 0)
        words_page.pack_start(sep_row, False, False, 0)

        capitalise = Gtk.CheckButton(label="Capitalise Each Word")
        number = Gtk.CheckButton(label="Add two digits on the end")
        words_page.pack_start(capitalise, False, False, 0)
        words_page.pack_start(number, False, False, 0)
        stack.add_titled(words_page, "words", "Passphrase")

        err = Gtk.Label(label="", xalign=0)
        err.get_style_context().add_class("error")
        outer.pack_start(err, False, False, 0)

        state = {"value": ""}

        def regenerate(*_):
            try:
                if stack.get_visible_child_name() == "words":
                    count = int(words.get_value())
                    state["value"] = hoard.passphrase(
                        count,
                        separator=separator.get_active_id() or "-",
                        capitalise=capitalise.get_active(),
                        number=number.get_active(),
                    )
                    bits = hoard.passphrase_bits(count)
                else:
                    options = {key: check.get_active() for key, check in toggles.items()}
                    options["exclude_ambiguous"] = ambiguous.get_active()
                    state["value"] = hoard.generate(int(length.get_value()), **options)
                    bits = hoard.password_bits(int(length.get_value()), **options)
                preview.set_text(state["value"])
                strength.set_text(f"{bits:.0f} bits of entropy")
                err.set_text("")
                use.set_sensitive(True)
            except hoard.HoardError as exc:
                # Refused rather than quietly handing back something weaker
                # than was asked for.
                state["value"] = ""
                preview.set_text("")
                strength.set_text("")
                message = str(exc)
                err.set_text(message[0].upper() + message[1:] + ".")
                use.set_sensitive(False)

        for widget in (*toggles.values(), ambiguous, capitalise, number):
            widget.connect("toggled", regenerate)
        for adjustment in (length, words):
            adjustment.connect("value-changed", regenerate)
        separator.connect("changed", regenerate)
        stack.connect("notify::visible-child", regenerate)

        again = Gtk.Button(label="Regenerate")
        again.connect("clicked", regenerate)
        outer.pack_start(again, False, False, 0)

        regenerate()
        dlg.get_content_area().add(outer)
        dlg.show_all()
        chosen = state["value"] if dlg.run() == Gtk.ResponseType.OK else None
        dlg.destroy()
        return chosen

    def item_dialog(self, existing: str | None = None) -> None:
        """
        One form for adding and editing, so the two cannot drift apart. That is
        how the window ended up able to create an item but never change one.
        """
        entry = self.entries().get(existing, {}) if existing else {}
        dlg = Gtk.Dialog(title="Edit item" if existing else "Add item",
                         transient_for=self, modal=True)
        dlg.add_button("Cancel", Gtk.ResponseType.CANCEL)
        confirm = dlg.add_button("Save", Gtk.ResponseType.OK)
        confirm.get_style_context().add_class("suggested-action")

        grid = Gtk.Grid(row_spacing=8, column_spacing=10)
        grid.set_border_width(14)
        fields = {}
        rows = (("name", "Name", existing or ""),
                ("username", "Username", entry.get("username", "")),
                ("url", "Website", entry.get("url", "")),
                ("totp", "2FA secret", entry.get("totp", "")))
        for i, (key, label, value) in enumerate(rows):
            grid.attach(Gtk.Label(label=label, xalign=0), 0, i, 1, 1)
            e = Gtk.Entry()
            e.set_width_chars(32)
            e.set_text(value)
            fields[key] = e
            grid.attach(e, 1, i, 1, 1)
        fields["totp"].set_placeholder_text("stored, not yet used to generate codes")

        row = len(rows)
        grid.attach(Gtk.Label(label="Password", xalign=0), 0, row, 1, 1)
        pw_box = Gtk.Box(spacing=6)
        pw = Gtk.Entry()
        pw.set_visibility(False)
        pw.set_width_chars(24)
        pw.set_text(entry.get("password", ""))
        pw_box.pack_start(pw, True, True, 0)
        gen = Gtk.Button(label="Generate")

        def generate_into_field(*_):
            chosen = self.generator_dialog(dlg)
            if chosen:
                pw.set_text(chosen)
                pw.set_visibility(True)

        gen.connect("clicked", generate_into_field)
        pw_box.pack_end(gen, False, False, 0)
        grid.attach(pw_box, 1, row, 1, 1)

        grid.attach(Gtk.Label(label="Note", xalign=0), 0, row + 1, 1, 1)
        note_view = Gtk.TextView()
        note_view.set_wrap_mode(Gtk.WrapMode.WORD)
        note_view.get_buffer().set_text(entry.get("note", ""))
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroller.set_min_content_height(70)
        scroller.set_shadow_type(Gtk.ShadowType.IN)
        scroller.add(note_view)
        grid.attach(scroller, 1, row + 1, 1, 1)

        err = Gtk.Label(label="", xalign=0)
        err.get_style_context().add_class("error")
        grid.attach(err, 0, row + 2, 2, 1)

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
            if name != existing and name in self.entries():
                err.set_text(f"An item called {name} already exists.")
                continue
            if not secret:
                err.set_text("Enter a password, or press Generate.")
                continue

            buf = note_view.get_buffer()
            note = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False).strip()

            updated = copy.deepcopy(self.vault)
            entries = updated.setdefault("entries", {})
            if existing and existing != name:
                # A rename, so the old key goes rather than leaving a duplicate.
                entries.pop(existing, None)
            record = {
                "password": secret,
                "username": fields["username"].get_text().strip(),
                "url": fields["url"].get_text().strip(),
                "note": note,
                "updated": int(time.time()),
            }
            totp = fields["totp"].get_text().strip()
            if totp:
                record["totp"] = totp
            entries[name] = record

            self.save(updated, self.password,
                      lambda: (self.note("Item saved", name), self.refresh_list()))
            break
        dlg.destroy()
        self.reset_autolock()

    def add_item_dialog(self) -> None:
        self.item_dialog()

    def edit_item_dialog(self, name: str) -> None:
        self.item_dialog(name)

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
