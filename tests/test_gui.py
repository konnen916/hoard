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
except Exception:  # pragma: no cover
    hoard_gui = None


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
        """A worker that raises must not die silently on its own thread."""
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
