# The window stops freezing

Design for moving key derivation off the GTK main thread. Written 9 August 2026.

## The problem, measured

`hoard_gui.py` has no threading. `unlock` calls `hoard.read_vault` and `save`
calls `hoard.write_vault`, both on the GTK main thread. On this machine:

```
argon2id at m=65536KiB t=3 p=4:  238 ms
full seal of a 200 entry vault:  246 ms
```

Every unlock and every save freezes the window for roughly a quarter of a
second. Adding, editing and deleting all save, so it freezes on each one. That
is past the point where people notice, and about fifteen frames during which the
window does not repaint at all: drag another window across it and you get a
smeared rectangle.

It gets worse on slower hardware, and worse again the day the Argon2 cost is
raised, which is the only direction that number ever moves.

## What is not changing

No visual changes. Same layout, same widgets, same system theme, same
keybindings. The window is not being redesigned, it is being stopped from going
dead.

`refresh_list` and `show_detail` stay on the main thread. They are pure UI and
they are fast. Only the three operations that derive a key move.

## The seam

```python
def run_off_main(work, on_done, on_error, dispatch=None):
    """
    Run work() on a worker thread and deliver the outcome on the GTK main loop.

    Nothing inside work() may touch a widget. GTK is not thread safe, so the
    callbacks are handed back through GLib.idle_add rather than being called
    from the worker.
    """
```

`dispatch` defaults to `GLib.idle_add` and exists so the function can be tested
without GTK. The tests pin three properties:

- a successful `work()` routes its return value to `on_done`
- an exception routes to `on_error` rather than escaping the thread
- both callbacks arrive **through the dispatcher**, never called inline

The third is the one that actually keeps GTK safe, so it is the one most worth
pinning. Calling a widget update from a worker thread produces corruption that
looks like a random bug months later, not a crash at the call site.

## Three things that make this more than wrapping a thread

### Snapshot the arguments

`save` currently does:

```python
hoard.write_vault(self.vault_path, self.vault, self.password)
```

If autolock fires while that runs, `self.password` becomes `None` underneath the
worker. The vault, path and password are captured into locals before the thread
starts, and the worker never reads `self`.

### Discard stale results

An operation that finishes after the vault has locked must not repaint a locked
window with decrypted contents. Every lock bumps a generation counter, each
operation captures the generation it started in, and a callback whose generation
no longer matches is dropped without touching the UI.

### Commit state only on success

This fixes a bug that already exists and that async would widen.

All three callers mutate before they save. `add_item_dialog` writes into
`self.vault["entries"]`, `delete_item` does `del self.vault["entries"][name]`,
and `change_master_dialog` assigns `self.password` before calling `save`. If the
write fails, memory and disk disagree and nothing says so. Today that window is
240 ms. Asynchronously it stays open until the worker returns.

So each operation builds the intended state, hands it to the worker, and assigns
it to `self.vault` or `self.password` only in `on_done`.

## Busy state

`save` returns a bool today and all three callers branch on it. They become
callbacks.

While an operation is in flight the control that triggered it is disabled and
the autolock timer is suspended. You cannot queue two saves, and you cannot lock
into the middle of one.

The unlock screen shows the button disabled with its label changed while the key
is derived. That is deliberate rather than a spinner: the operation takes a
quarter second, and a spinner that appears and vanishes that fast is noise.

## Verification

Not a screenshot. **Count GTK main loop iterations during an unlock.** If the
derive is blocking, the loop does not turn and the count is zero. If it is off
the main thread, the loop keeps running.

That measures the property the whole change exists for, and it fails loudly if
somebody later moves the crypto back onto the main thread, which is exactly the
regression worth guarding.

A screenshot of the window taken mid-unlock is a secondary sanity check, not the
test.

## Out of scope

TOTP, import and export, and the standalone decrypter. Those are the next round,
headlined by reading a KeePass database so people can leave KeePassXC without
retyping everything.
