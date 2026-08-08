# Non Blocking Window Implementation Plan

> Work through this one task at a time. Each task is a full test cycle: write
> the failing test, watch it fail, write the smallest thing that passes it,
> watch it pass, commit. Checkboxes track progress.

**Goal:** Move key derivation off the GTK main thread so the window never blanks for a quarter second during unlock or save.

**Architecture:** One helper, `run_off_main`, runs work on a daemon thread and hands the outcome back through a dispatcher, which is `GLib.idle_add` in the application and a synchronous stub in the tests. `HoardWindow` grows a generation counter and a busy flag so results arriving after a lock are discarded and two operations cannot overlap.

**Tech Stack:** Python 3 stdlib `threading`, PyGObject, GTK 3. No new dependencies.

## Global Constraints

- No new third-party dependencies.
- No em-dashes or en-dashes anywhere, including comments and commit messages.
- Commits carry no trailers, author `konnen916 <300166086+konnen916@users.noreply.github.com>`.
- Nothing inside a worker may touch a GTK widget or read `self`.
- No visual changes: same layout, widgets, theme and keybindings.
- Tests that need `gi` skip cleanly when it is absent.

---

### Task 1: `run_off_main`

**Files:**
- Modify: `hoard_gui.py` (imports, and a module level function above `class Log`)
- Test: `tests/test_gui.py` (create)

**Interfaces:**
- Produces: `run_off_main(work, on_done, on_error, dispatch) -> threading.Thread`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_gui.py`:

```python
"""
Tests for the window's threading seam.

The window itself is not exercised here. What matters is that work runs off the
main thread and that its result comes back through the dispatcher, because
touching a GTK widget from a worker produces corruption that surfaces as a
random bug months later rather than as a crash at the call site.
"""

import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    import gi

    gi.require_version("Gtk", "3.0")
    import hoard_gui
except Exception as exc:  # pragma: no cover
    hoard_gui = None
    _why = exc


@unittest.skipIf(hoard_gui is None, "needs pygobject and gtk3")
class TestRunOffMain(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.dispatch = lambda fn, arg: self.calls.append(("dispatched", fn, arg))

    def test_a_result_is_routed_to_on_done(self):
        got = []
        t = hoard_gui.run_off_main(lambda: 42, got.append, got.append,
                                   dispatch=lambda fn, arg: fn(arg))
        t.join(5)
        self.assertEqual(got, [42])

    def test_an_exception_is_routed_to_on_error_not_raised(self):
        """A worker that raises must not kill the thread silently."""
        errors = []
        boom = ValueError("nope")

        def work():
            raise boom

        t = hoard_gui.run_off_main(work, lambda v: self.fail("on_done ran"),
                                   errors.append, dispatch=lambda fn, arg: fn(arg))
        t.join(5)
        self.assertEqual(errors, [boom])

    def test_callbacks_go_through_the_dispatcher_never_inline(self):
        """
        This is the property that keeps GTK safe. If a callback is ever invoked
        from the worker instead of handed to the dispatcher, widget updates
        happen off the main thread.
        """
        t = hoard_gui.run_off_main(lambda: "v", lambda v: None, lambda e: None,
                                   dispatch=self.dispatch)
        t.join(5)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][0], "dispatched")
        self.assertEqual(self.calls[0][2], "v")

    def test_the_work_runs_on_another_thread(self):
        where = []
        t = hoard_gui.run_off_main(lambda: where.append(threading.current_thread().name),
                                   lambda v: None, lambda e: None,
                                   dispatch=lambda fn, arg: fn(arg))
        t.join(5)
        self.assertEqual(len(where), 1)
        self.assertNotEqual(where[0], threading.current_thread().name)

    def test_it_returns_immediately_rather_than_waiting(self):
        """If this blocks, the whole change is pointless."""
        import time
        started = time.perf_counter()
        t = hoard_gui.run_off_main(lambda: time.sleep(0.4), lambda v: None, lambda e: None,
                                   dispatch=lambda fn, arg: fn(arg))
        elapsed = time.perf_counter() - started
        self.assertLess(elapsed, 0.1, "run_off_main blocked the caller")
        t.join(5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd /home/woncat/hoard && python3 -m unittest tests.test_gui -v`
Expected: FAIL, `module 'hoard_gui' has no attribute 'run_off_main'`

- [ ] **Step 3: Add the import and the helper**

Add `import threading` to the stdlib imports in `hoard_gui.py`, after `import sys`.

Add above `class Log:`:

```python
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
```

- [ ] **Step 4: Run to verify they pass**

Run: `cd /home/woncat/hoard && python3 -m unittest discover tests -v 2>&1 | tail -4`
Expected: PASS, 61 tests

- [ ] **Step 5: Commit**

```bash
cd /home/woncat/hoard
git add hoard_gui.py tests/test_gui.py
git commit -m "Add the threading seam the window will derive keys on

Work runs on a daemon thread and the outcome comes back through a
dispatcher, GLib.idle_add in the application and a synchronous stub in the
tests. The test that matters is the one pinning that callbacks arrive
through the dispatcher rather than inline, because a widget touched from a
worker corrupts quietly rather than crashing where you can see it."
```

---

### Task 2: Unlock stops blocking

**Files:**
- Modify: `hoard_gui.py` `__init__`, `unlock`, `lock`
- Test: `tests/test_gui.py`

**Interfaces:**
- Consumes: `run_off_main` from Task 1.
- Produces: `HoardWindow._generation`, `HoardWindow._busy`, `HoardWindow._set_busy(busy, button, label)`

- [ ] **Step 1: Add state in `__init__`**

After `self._autolock: int | None = None`:

```python
        # Bumped on every lock. A result whose generation no longer matches
        # arrived after the vault closed and must not repaint the window.
        self._generation = 0
        self._busy = False
```

- [ ] **Step 2: Add `_set_busy` above `unlock`**

```python
    def _set_busy(self, busy: bool, button: Gtk.Button | None = None,
                  label: str | None = None) -> None:
        """
        Mark an operation in flight, and optionally disable the control that
        started it.

        The button is optional because only unlock has one that outlives the
        operation. The dialogs all destroy themselves before the write
        finishes, and the delete button is rebuilt by refresh_list, so there
        would be nothing left to re-enable. For those the busy flag alone stops
        a second operation starting.

        No spinner: these take a quarter second, and something that appears and
        vanishes that fast reads as a glitch rather than as progress.
        """
        self._busy = busy
        if button is not None:
            button.set_sensitive(not busy)
            if label is not None:
                button.set_label(label)
```

- [ ] **Step 3: Replace `unlock`**

```python
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
```

- [ ] **Step 4: Bump the generation in `lock`**

In `lock`, immediately after `def lock(self, why: str = "Locked") -> None:` opens, add as the first statement:

```python
        self._generation += 1
```

- [ ] **Step 5: Write the verification test**

Append to `tests/test_gui.py`, before the `if __name__` block:

```python
@unittest.skipIf(hoard_gui is None, "needs pygobject and gtk3")
class TestMainLoopKeepsTurning(unittest.TestCase):
    """
    The whole point of the change. If the derive runs on the main thread the
    loop does not turn while it happens, so counting iterations measures the
    actual property rather than something adjacent to it.
    """

    def test_the_loop_runs_during_a_key_derivation(self):
        from gi.repository import GLib
        import hoard

        ticks = []
        loop = GLib.MainLoop()

        def tick():
            ticks.append(1)
            return True

        GLib.timeout_add(5, tick)

        def work():
            # The real cost, not a sleep. A sleep would pass even if the code
            # were wrong about which thread it runs on.
            return hoard.derive_key("pw", b"x" * 16, hoard.ARGON)

        hoard_gui.run_off_main(work, lambda v: loop.quit(), lambda e: loop.quit(),
                               GLib.idle_add)
        GLib.timeout_add_seconds(10, lambda: (loop.quit(), False)[1])
        loop.run()

        self.assertGreater(len(ticks), 5,
                           "the main loop stalled, the derive is still blocking it")
```

- [ ] **Step 6: Run the suite**

Run: `cd /home/woncat/hoard && python3 -m unittest discover tests 2>&1 | tail -4`
Expected: PASS, 62 tests

- [ ] **Step 7: Commit**

```bash
cd /home/woncat/hoard
git add hoard_gui.py tests/test_gui.py
git commit -m "Derive the key off the main thread when unlocking

The window no longer blanks for a quarter second on unlock. Arguments are
captured before the thread starts so autolock cannot pull the password out
from under the worker, and every lock bumps a generation counter so a
result arriving after the vault closed is dropped instead of repainting a
locked window with decrypted contents.

The test counts main loop iterations during a real derive rather than
taking a screenshot, because that measures the property directly and fails
if anyone moves the crypto back."
```

---

### Task 3: Saving stops blocking, and stops lying on failure

**Files:**
- Modify: `hoard_gui.py` `save`, `add_item_dialog`, `delete_item`, `change_master_dialog`

**Interfaces:**
- Consumes: `run_off_main`, `_set_busy`, `_generation`.
- Produces: `save(vault, password, on_saved)`

- [ ] **Step 1: Replace `save`**

```python
    def save(self, vault: dict, password: str, on_saved) -> None:
        """
        Write the vault off the main thread, then hand the caller the state to
        commit.

        The caller passes the vault it intends rather than mutating self.vault
        and hoping. A failed write used to leave memory and disk disagreeing
        with nothing saying so, and going async would have widened that window
        from a quarter second to however long the worker takes.

        No button is disabled here. Every caller destroys its dialog before the
        write finishes, so there is nothing left to re-enable; the busy flag is
        what stops a second write starting.
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
```

- [ ] **Step 2: Rework `add_item_dialog`**

Replace the block from `self.vault.setdefault("entries", {})[name] = {` through `break` with:

```python
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
```

`save` here is the dialog's Save button, already bound at the top of the method.

- [ ] **Step 3: Rework `delete_item`**

Replace `del self.vault["entries"][name]` through the end of the `if self.save():` block with:

```python
        updated = copy.deepcopy(self.vault)
        del updated["entries"][name]

        def after() -> None:
            self.note("Item deleted", name)
            self.selected = None
            for child in self.detail.get_children():
                self.detail.remove(child)
            self.refresh_list()

        self.save(updated, self.password, after)
```

No button is passed. The Delete button lives inside `show_detail` and is
destroyed by the `refresh_list()` in `after`, so there would be nothing left to
re-enable, and the action is also reachable from the menubar where no button
exists at all.

- [ ] **Step 4: Rework `change_master_dialog`**

Replace `self.password = first.get_text()` and the `if self.save():` block with:

```python
            new_password = first.get_text()
            self.save(self.vault, new_password,
                      lambda: self.note("Master password changed, vault re-encrypted"))
            break
```

The password is now assigned by `save` on success only. Previously it was set before the write, so a failed write left the window believing the password had changed when the file on disk still used the old one.

- [ ] **Step 5: Add the import**

Add `import copy` to the stdlib imports in `hoard_gui.py`, after `import hashlib`.

- [ ] **Step 6: Run the suite and check the window still builds**

```bash
cd /home/woncat/hoard
python3 -m unittest discover tests 2>&1 | tail -4
python3 -c "
import gi; gi.require_version('Gtk','3.0')
from gi.repository import Gtk
import hoard_gui, pathlib
w = hoard_gui.HoardWindow(pathlib.Path('/tmp/nope'))
w.show_all()
print('window built, no exception')
"
```
Expected: tests pass, window builds

- [ ] **Step 7: Commit**

```bash
cd /home/woncat/hoard
git add hoard_gui.py
git commit -m "Write the vault off the main thread, and commit state only on success

Adding, deleting and changing the master password no longer freeze the
window while the key is derived.

Callers now build the vault they intend and hand it over, rather than
mutating self.vault and then saving. A failed write previously left memory
and disk disagreeing with nothing saying so, and the master password was
assigned before the write, so a failure left the window believing a change
that had not reached the file."
```

---

## Verification

```bash
cd /home/woncat/hoard
python3 -m unittest discover tests 2>&1 | tail -3
git log --format='%h %an | %s | trailers:[%(trailers:only)]' -4
git log -p -4 | grep -cP '\x{2014}|\x{2013}'
```
Expected: all tests pass, every commit by `konnen916`, no trailers, dash count `0`.
