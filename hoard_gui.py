#!/usr/bin/env python3
"""
hoard-gui: a window for the hoard vault.

All crypto is imported from hoard.py. Nothing here derives a key, chooses a
nonce, or touches a cipher. If this file has a bug it is a bug about pixels.
"""

from __future__ import annotations

import hashlib
import os
import platform
import sys
import time
from pathlib import Path

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
from gi.repository import Gdk, GLib, Gtk  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hoard  # noqa: E402

AUTOLOCK_SECONDS = 300
CLIP_SECONDS = hoard.CLIP_SECONDS

# Warm dark. Most dark UIs are blue grey; a hoard is gold, so this one leans
# brown and the accent is amber, which is also what old terminals glowed.
CSS = b"""
* {
  font-family: "DejaVu Sans Mono", "Liberation Mono", monospace;
  font-size: 13px;
}
window, .root { background: #14110d; color: #e6ddcb; }

.strip {
  background: #1a1611;
  border-bottom: 1px solid #332c23;
  padding: 7px 12px;
}
.strip-bottom {
  background: #1a1611;
  border-top: 1px solid #332c23;
  border-bottom: 0;
  padding: 6px 12px;
}
.wordmark { color: #d9a441; font-weight: bold; letter-spacing: 2px; }
.meta { color: #8b8172; font-size: 11px; }
.micro {
  color: #8b8172; font-size: 10px;
  letter-spacing: 2px; font-weight: bold;
}

/* Locked state is the whole window, not a dialog over a greyed one. */
.lockpane { background: #14110d; }
.locktitle {
  color: #d9a441; font-size: 26px; font-weight: bold; letter-spacing: 6px;
}
.locksub { color: #8b8172; font-size: 11px; letter-spacing: 1px; }

entry {
  background: #0d0b08;
  color: #e6ddcb;
  border: 1px solid #332c23;
  border-radius: 0;
  padding: 9px 10px;
  caret-color: #d9a441;
}
entry:focus { border-color: #d9a441; }

button {
  background: #221d17;
  color: #e6ddcb;
  border: 1px solid #332c23;
  border-radius: 0;
  padding: 8px 14px;
}
button:hover { background: #2c261e; border-color: #4a4034; }
button:active { background: #d9a441; color: #14110d; }
button.primary { background: #d9a441; color: #14110d; border-color: #d9a441; font-weight: bold; }
button.primary:hover { background: #e8b75a; border-color: #e8b75a; }
button.danger { color: #b5503a; }
button.danger:hover { background: #2a1a16; border-color: #b5503a; }

list { background: #14110d; }
list row { padding: 9px 12px; border-left: 3px solid transparent; }
list row:hover { background: #1c1812; }
list row:selected { background: #221d17; border-left: 3px solid #d9a441; color: #e6ddcb; }
.entryname { color: #e6ddcb; }
.entrysub { color: #8b8172; font-size: 11px; }

.detail { background: #14110d; padding: 18px 20px; }
.fieldlabel { color: #8b8172; font-size: 10px; letter-spacing: 2px; font-weight: bold; }
.fieldvalue { color: #e6ddcb; }
.secret { color: #d9a441; }
.title { color: #e6ddcb; font-size: 17px; font-weight: bold; }
.rule { background: #332c23; min-height: 1px; }
.error { color: #b5503a; font-size: 11px; }
.empty { color: #8b8172; }
scrolledwindow { border: 0; }
paned separator { background: #332c23; min-width: 1px; }
"""


def now() -> str:
    return time.strftime("%H:%M:%S")


class Log:
    """
    What the app just did, in the open.

    Entry names are shown locally because that is useful to the person looking
    at their own screen. They are redacted out of the exported diagnostics,
    because a list of the sites you have accounts on is not something you
    should paste into a bug report.
    """

    def __init__(self) -> None:
        self.lines: list[tuple[str, str, str | None]] = []

    def add(self, message: str, name: str | None = None) -> None:
        self.lines.append((now(), message, name))

    def latest(self) -> str:
        if not self.lines:
            return "ready"
        ts, msg, name = self.lines[-1]
        return f"{ts}  {msg}" + (f"  {name}" if name else "")

    def diagnostics(self, vault: Path) -> str:
        out = [
            "hoard diagnostics",
            f"generated     {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"python        {platform.python_version()}",
            f"platform      {platform.platform()}",
            f"gtk           {Gtk.get_major_version()}.{Gtk.get_minor_version()}",
            f"session       {os.environ.get('XDG_SESSION_TYPE', 'unknown')}",
            f"desktop       {os.environ.get('XDG_CURRENT_DESKTOP', 'unknown')}",
            f"clipboard     wl-copy={bool(_which('wl-copy'))} xclip={bool(_which('xclip'))}",
            f"vault exists  {vault.exists()}",
            f"vault size    {vault.stat().st_size if vault.exists() else 0} bytes",
            f"argon2id      m={hoard.ARGON['m']}KiB t={hoard.ARGON['t']} p={hoard.ARGON['p']}",
            "",
            "activity (entry names redacted)",
        ]
        for ts, msg, name in self.lines[-40:]:
            tag = ""
            if name:
                # Stable per name, so repeated actions on one entry are
                # traceable without revealing which entry it was.
                tag = "  entry:" + hashlib.sha256(name.encode()).hexdigest()[:6]
            out.append(f"  {ts}  {msg}{tag}")
        return "\n".join(out)


def _which(name: str):
    from shutil import which
    return which(name)


def micro(text: str) -> Gtk.Label:
    lbl = Gtk.Label(label=text, xalign=0)
    lbl.get_style_context().add_class("micro")
    return lbl


class HoardWindow(Gtk.Window):
    def __init__(self, vault_path: Path) -> None:
        super().__init__(title="hoard")
        self.vault_path = vault_path
        self.password: str | None = None
        self.vault: dict | None = None
        self.selected: str | None = None
        self.log = Log()
        self._autolock_source: int | None = None

        self.set_default_size(880, 560)
        self.set_position(Gtk.WindowPosition.CENTER)
        self.connect("destroy", Gtk.main_quit)
        self.connect("key-press-event", self.on_key)

        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.stack.set_transition_duration(120)
        self.add(self.stack)

        self.stack.add_named(self.build_lock(), "lock")
        self.stack.add_named(self.build_vault(), "vault")
        self.stack.set_visible_child_name("lock")

    # ------------------------------------------------------------ lock view

    def build_lock(self) -> Gtk.Widget:
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        outer.get_style_context().add_class("lockpane")

        centre = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        centre.set_valign(Gtk.Align.CENTER)
        centre.set_halign(Gtk.Align.CENTER)
        centre.set_size_request(420, -1)

        title = Gtk.Label(label="HOARD")
        title.get_style_context().add_class("locktitle")
        centre.pack_start(title, False, False, 0)

        sub = Gtk.Label(label=str(self.vault_path))
        sub.get_style_context().add_class("locksub")
        sub.set_margin_top(6)
        sub.set_margin_bottom(26)
        centre.pack_start(sub, False, False, 0)

        self.pw_entry = Gtk.Entry()
        self.pw_entry.set_visibility(False)
        self.pw_entry.set_placeholder_text("master password")
        self.pw_entry.connect("activate", lambda *_: self.unlock())
        centre.pack_start(self.pw_entry, False, False, 0)

        btn = Gtk.Button(label="Unlock")
        btn.get_style_context().add_class("primary")
        btn.set_margin_top(10)
        btn.connect("clicked", lambda *_: self.unlock())
        centre.pack_start(btn, False, False, 0)

        self.lock_error = Gtk.Label(label="")
        self.lock_error.get_style_context().add_class("error")
        self.lock_error.set_margin_top(12)
        centre.pack_start(self.lock_error, False, False, 0)

        outer.pack_start(centre, True, True, 0)
        return outer

    # ----------------------------------------------------------- vault view

    def build_vault(self) -> Gtk.Widget:
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        root.get_style_context().add_class("root")

        # top strip
        top = Gtk.Box(spacing=12)
        top.get_style_context().add_class("strip")
        mark = Gtk.Label(label="HOARD", xalign=0)
        mark.get_style_context().add_class("wordmark")
        top.pack_start(mark, False, False, 0)
        self.count_label = Gtk.Label(label="", xalign=0)
        self.count_label.get_style_context().add_class("meta")
        top.pack_start(self.count_label, False, False, 0)

        lock_btn = Gtk.Button(label="Lock")
        lock_btn.connect("clicked", lambda *_: self.lock("locked manually"))
        top.pack_end(lock_btn, False, False, 0)
        add_btn = Gtk.Button(label="Add entry")
        add_btn.get_style_context().add_class("primary")
        add_btn.connect("clicked", lambda *_: self.add_entry_dialog())
        top.pack_end(add_btn, False, False, 0)
        root.pack_start(top, False, False, 0)

        # body
        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        paned.set_position(260)

        left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.filter_entry = Gtk.Entry()
        self.filter_entry.set_placeholder_text("filter")
        self.filter_entry.set_margin_top(10)
        self.filter_entry.set_margin_start(10)
        self.filter_entry.set_margin_end(10)
        self.filter_entry.connect("changed", lambda *_: self.refresh_list())
        left.pack_start(self.filter_entry, False, False, 0)

        self.listbox = Gtk.ListBox()
        self.listbox.connect("row-selected", self.on_row_selected)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.add(self.listbox)
        left.pack_start(scroll, True, True, 0)
        paned.pack1(left, False, False)

        self.detail = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.detail.get_style_context().add_class("detail")
        detail_scroll = Gtk.ScrolledWindow()
        detail_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        detail_scroll.add(self.detail)
        paned.pack2(detail_scroll, True, False)

        root.pack_start(paned, True, True, 0)

        # activity strip: the signature element, always visible
        bottom = Gtk.Box(spacing=10)
        bottom.get_style_context().add_class("strip-bottom")
        self.log_label = Gtk.Label(label="ready", xalign=0)
        self.log_label.get_style_context().add_class("meta")
        self.log_label.set_ellipsize(3)  # PANGO_ELLIPSIZE_END
        bottom.pack_start(self.log_label, True, True, 0)
        diag = Gtk.Button(label="Copy diagnostics")
        diag.connect("clicked", lambda *_: self.copy_diagnostics())
        bottom.pack_end(diag, False, False, 0)
        root.pack_start(bottom, False, False, 0)

        return root

    # -------------------------------------------------------------- actions

    def note(self, message: str, name: str | None = None) -> None:
        self.log.add(message, name)
        if hasattr(self, "log_label"):
            self.log_label.set_text(self.log.latest())

    def unlock(self) -> None:
        pw = self.pw_entry.get_text()
        if not pw:
            self.lock_error.set_text("enter the master password")
            return
        try:
            self.vault = hoard.read_vault(self.vault_path, pw)
        except hoard.HoardError as exc:
            self.lock_error.set_text(str(exc))
            self.log.add("unlock failed")
            return
        self.password = pw
        self.pw_entry.set_text("")
        self.lock_error.set_text("")
        self.note("vault unlocked")
        self.refresh_list()
        self.stack.set_visible_child_name("vault")
        self.reset_autolock()

    def lock(self, why: str = "locked") -> None:
        self.password = None
        self.vault = None
        self.selected = None
        for child in self.detail.get_children():
            self.detail.remove(child)
        self.log.add(why)
        self.stack.set_visible_child_name("lock")
        self.pw_entry.grab_focus()
        if self._autolock_source:
            GLib.source_remove(self._autolock_source)
            self._autolock_source = None

    def reset_autolock(self) -> None:
        if self._autolock_source:
            GLib.source_remove(self._autolock_source)
        self._autolock_source = GLib.timeout_add_seconds(
            AUTOLOCK_SECONDS, lambda: (self.lock(f"auto locked after {AUTOLOCK_SECONDS}s idle"), False)[1]
        )

    def entries(self) -> dict:
        return (self.vault or {}).get("entries", {})

    def refresh_list(self) -> None:
        for child in self.listbox.get_children():
            self.listbox.remove(child)
        needle = self.filter_entry.get_text().lower()
        names = sorted(n for n in self.entries() if needle in n.lower())

        total = len(self.entries())
        self.count_label.set_text(
            f"{total} entries" if needle == "" else f"{len(names)} of {total}"
        )

        if not names:
            row = Gtk.ListBoxRow()
            row.set_selectable(False)
            lbl = Gtk.Label(
                label="nothing here yet\nuse Add entry" if total == 0 else "no match",
                xalign=0,
            )
            lbl.get_style_context().add_class("empty")
            lbl.set_margin_top(14)
            lbl.set_margin_start(12)
            row.add(lbl)
            self.listbox.add(row)
        for name in names:
            self.listbox.add(self.make_row(name))
        self.listbox.show_all()

    def make_row(self, name: str) -> Gtk.ListBoxRow:
        row = Gtk.ListBoxRow()
        row.name_value = name  # type: ignore[attr-defined]
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        top = Gtk.Label(label=name, xalign=0)
        top.get_style_context().add_class("entryname")
        box.pack_start(top, False, False, 0)
        user = self.entries()[name].get("username") or ""
        if user:
            sub = Gtk.Label(label=user, xalign=0)
            sub.get_style_context().add_class("entrysub")
            box.pack_start(sub, False, False, 0)
        row.add(box)
        return row

    def on_row_selected(self, _box, row) -> None:
        if row is None or not hasattr(row, "name_value"):
            return
        self.selected = row.name_value  # type: ignore[attr-defined]
        self.show_detail(self.selected)
        self.reset_autolock()

    def show_detail(self, name: str) -> None:
        for child in self.detail.get_children():
            self.detail.remove(child)
        entry = self.entries().get(name)
        if entry is None:
            return

        title = Gtk.Label(label=name, xalign=0)
        title.get_style_context().add_class("title")
        self.detail.pack_start(title, False, False, 0)

        rule = Gtk.Box()
        rule.get_style_context().add_class("rule")
        rule.set_margin_top(12)
        rule.set_margin_bottom(16)
        self.detail.pack_start(rule, False, False, 0)

        self._field("USERNAME", entry.get("username") or "not set")
        self._field("URL", entry.get("url") or "not set")

        self.detail.pack_start(micro("PASSWORD"), False, False, 0)
        pw_row = Gtk.Box(spacing=8)
        pw_row.set_margin_top(4)
        pw_row.set_margin_bottom(16)
        self.secret_label = Gtk.Label(label="•" * 16, xalign=0)
        self.secret_label.get_style_context().add_class("secret")
        self.secret_label.set_selectable(True)
        pw_row.pack_start(self.secret_label, True, True, 0)

        reveal = Gtk.Button(label="Reveal")
        reveal.connect("clicked", lambda b: self.toggle_reveal(b, name))
        pw_row.pack_end(reveal, False, False, 0)
        copy = Gtk.Button(label="Copy")
        copy.get_style_context().add_class("primary")
        copy.connect("clicked", lambda *_: self.copy_password(name))
        pw_row.pack_end(copy, False, False, 0)
        self.detail.pack_start(pw_row, False, False, 0)

        if entry.get("note"):
            self._field("NOTE", entry["note"])
        if entry.get("updated"):
            self._field("UPDATED", time.strftime("%Y-%m-%d", time.localtime(entry["updated"])))

        delete = Gtk.Button(label="Delete entry")
        delete.get_style_context().add_class("danger")
        delete.set_halign(Gtk.Align.START)
        delete.set_margin_top(10)
        delete.connect("clicked", lambda *_: self.delete_entry(name))
        self.detail.pack_start(delete, False, False, 0)

        self.detail.show_all()

    def _field(self, label: str, value: str) -> None:
        self.detail.pack_start(micro(label), False, False, 0)
        val = Gtk.Label(label=value, xalign=0)
        val.get_style_context().add_class("fieldvalue")
        val.set_selectable(True)
        val.set_line_wrap(True)
        val.set_margin_top(4)
        val.set_margin_bottom(16)
        self.detail.pack_start(val, False, False, 0)

    def toggle_reveal(self, button: Gtk.Button, name: str) -> None:
        showing = button.get_label() == "Hide"
        if showing:
            self.secret_label.set_text("•" * 16)
            button.set_label("Reveal")
            self.note("password hidden", name)
        else:
            self.secret_label.set_text(self.entries()[name]["password"])
            button.set_label("Hide")
            self.note("password revealed on screen", name)
        self.reset_autolock()

    def copy_password(self, name: str) -> None:
        secret = self.entries()[name]["password"]
        if hoard.clipboard_copy(secret):
            self.note(f"copied to clipboard, clearing in {CLIP_SECONDS}s", name)
        else:
            # No wl-copy or xclip. GTK can still copy, but nothing will wipe it.
            Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text(secret, -1)
            self.note("copied via gtk, this one will not auto clear", name)
        self.reset_autolock()

    def save(self) -> bool:
        try:
            hoard.write_vault(self.vault_path, self.vault, self.password)
            return True
        except Exception as exc:
            self.note(f"save failed: {exc}")
            return False

    def add_entry_dialog(self) -> None:
        dlg = Gtk.Dialog(title="Add entry", transient_for=self, modal=True)
        dlg.add_button("Cancel", Gtk.ResponseType.CANCEL)
        ok = dlg.add_button("Save entry", Gtk.ResponseType.OK)
        ok.get_style_context().add_class("primary")
        box = dlg.get_content_area()
        box.set_spacing(8)
        box.set_border_width(16)

        fields = {}
        for key, placeholder in (
            ("name", "name, for example github"),
            ("username", "username"),
            ("url", "url"),
        ):
            box.pack_start(micro(key.upper()), False, False, 0)
            e = Gtk.Entry()
            e.set_placeholder_text(placeholder)
            fields[key] = e
            box.pack_start(e, False, False, 0)

        box.pack_start(micro("PASSWORD"), False, False, 0)
        pw_row = Gtk.Box(spacing=8)
        pw = Gtk.Entry()
        pw.set_visibility(False)
        pw.set_placeholder_text("password")
        pw_row.pack_start(pw, True, True, 0)
        gen = Gtk.Button(label="Generate")
        gen.connect("clicked", lambda *_: (pw.set_text(hoard.generate(24)), pw.set_visibility(True)))
        pw_row.pack_end(gen, False, False, 0)
        box.pack_start(pw_row, False, False, 0)

        err = Gtk.Label(label="")
        err.get_style_context().add_class("error")
        box.pack_start(err, False, False, 0)

        dlg.show_all()
        while True:
            if dlg.run() != Gtk.ResponseType.OK:
                break
            name = fields["name"].get_text().strip()
            secret = pw.get_text()
            if not name:
                err.set_text("a name is required")
                continue
            if name in self.entries():
                err.set_text(f"{name} already exists")
                continue
            if not secret:
                err.set_text("a password is required, or press Generate")
                continue
            self.vault.setdefault("entries", {})[name] = {
                "password": secret,
                "username": fields["username"].get_text().strip(),
                "url": fields["url"].get_text().strip(),
                "note": "",
                "updated": int(time.time()),
            }
            if self.save():
                self.note("entry saved", name)
                self.refresh_list()
            break
        dlg.destroy()
        self.reset_autolock()

    def delete_entry(self, name: str) -> None:
        confirm = Gtk.MessageDialog(
            transient_for=self, modal=True,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.OK_CANCEL,
            text=f"Delete {name}?",
        )
        confirm.format_secondary_text("The password is gone once the vault is written.")
        response = confirm.run()
        confirm.destroy()
        if response != Gtk.ResponseType.OK:
            return
        del self.vault["entries"][name]
        if self.save():
            self.note("entry deleted", name)
            self.selected = None
            for child in self.detail.get_children():
                self.detail.remove(child)
            self.refresh_list()

    def copy_diagnostics(self) -> None:
        text = self.log.diagnostics(self.vault_path)
        Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text(text, -1)
        self.note("diagnostics copied, entry names redacted")

    def on_key(self, _widget, event) -> bool:
        ctrl = event.state & Gdk.ModifierType.CONTROL_MASK
        key = Gdk.keyval_name(event.keyval)
        if ctrl and key == "l":
            self.lock("locked with ctrl+l")
            return True
        if ctrl and key == "f" and self.stack.get_visible_child_name() == "vault":
            self.filter_entry.grab_focus()
            return True
        if ctrl and key == "c" and self.selected:
            self.copy_password(self.selected)
            return True
        if key == "Escape" and self.stack.get_visible_child_name() == "vault":
            self.lock("locked with escape")
            return True
        return False


def main() -> int:
    vault_path = Path(sys.argv[1]) if len(sys.argv) > 1 else hoard.DEFAULT_VAULT
    if not vault_path.exists():
        print(f"no vault at {vault_path}", file=sys.stderr)
        print("create one first:  ./hoard.py init", file=sys.stderr)
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
