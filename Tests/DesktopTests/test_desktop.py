"""Offscreen UI + actual CLI integration checks; no fixtures in live targets."""
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"desktop"))
from PySide6.QtCore import QSettings, QProcess
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QPushButton
from tripwire_desktop import Engine, Dashboard, Overlay

app=QApplication.instance() or QApplication([])

class DesktopTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        QSettings.setDefaultFormat(QSettings.Format.IniFormat)
        QSettings.setPath(QSettings.Format.IniFormat,QSettings.Scope.UserScope,self.temp.name)
        self.engine=Engine(Path(os.environ["TRIPWIRE_TEST_CLI"]),Path(self.temp.name)/"private"/"evidence.sqlite")
        self.dashboard=Dashboard(self.engine); self.overlay=Overlay(self.engine,self.dashboard)
    def tearDown(self):
        self.engine.shutdown(); self.overlay.timer.stop(); self.overlay.close(); self.dashboard.close(); self.temp.cleanup()
    def wait_for(self,predicate,timeout=8):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            QTest.qWait(50)
            if predicate(): return
        self.fail("Timed out waiting for real CLI state")
    def test_layouts_controls_fit_and_only_expanded_shows_shrink(self):
        for mode in Overlay.LAYOUTS:
            self.overlay.change_layout(mode); self.overlay.show(); QTest.qWait(50)
            self.assertFalse(self.overlay.shrink.isVisible())
            for control in self.overlay.well.findChildren(QPushButton):
                if not control.isVisible(): continue
                self.assertTrue(self.overlay.well.rect().contains(control.geometry()),f"{mode}: clipped {control.text()} {control.geometry()}")
            width=self.overlay.width(); self.overlay.expand_now(); QTest.qWait(25)
            self.assertTrue(self.overlay.shrink.isVisible()); self.assertGreaterEqual(self.overlay.width(),width)
            for control in self.overlay.well.findChildren(QPushButton):
                if control.isVisible(): self.assertTrue(self.overlay.well.rect().contains(control.geometry()),f"{mode}: clipped expanded {control.text()}")
            self.overlay.shrink_now(); self.assertEqual(self.overlay.width(),width)
    def test_real_metrics_continue_while_overlay_hidden_and_dashboard_reused(self):
        self.engine.start(); self.overlay.show()
        self.wait_for(lambda: bool(self.engine.snapshot) and len(self.engine.history)>=2)
        self.assertEqual(self.engine.snapshot["sampledAt"],"NEVER")
        self.assertFalse((Path(self.temp.name)/"private"/"evidence.sqlite").exists())
        self.assertTrue(any(s["visibility"]=="UNAVAILABLE" for s in self.engine.snapshot["sensors"]))
        old=self.engine.history[-1][0]; dashboard_id=id(self.dashboard)
        self.overlay.inspect("Files"); self.assertFalse(self.overlay.isVisible())
        self.wait_for(lambda: self.engine.history[-1][0] >= old+4)
        self.overlay.show(); self.overlay.inspect("Checks")
        self.assertEqual(id(self.overlay.dashboard),dashboard_id)
        self.assertEqual(self.dashboard.page,"Checks")
        self.dashboard.list.setCurrentRow(1)
        selected=self.dashboard.selection
        self.engine.snapshot["sensors"][0]["detail"] += " (refresh)"
        self.dashboard.refresh()
        self.assertEqual(self.dashboard.selection,selected)
        self.assertIn("WHAT IT CHECKS",self.dashboard.details.toPlainText())
        self.assertIsNotNone(self.engine.fresh_metric().get("cpuPercent"))
        if os.environ.get("TRIPWIRE_RENDER_PATH"):
            self.overlay.change_layout("Super compact"); self.overlay.show(); QTest.qWait(50)
            self.overlay.grab().save(os.environ["TRIPWIRE_RENDER_PATH"])
    def test_owned_monitor_records_real_sources_and_stops_with_partial_pipe_message(self):
        self.engine.start(); self.engine.toggle_monitor()
        self.wait_for(lambda: self.engine.snapshot.get("sampledAt", "NEVER") != "NEVER",20)
        self.assertTrue(any(r["observation"]["eventClass"] == "EXEC" for r in self.engine.snapshot["inventory"]))
        self.engine.monitor.write(b"st"); QTest.qWait(50); self.engine.monitor.write(b"op\n")
        self.wait_for(lambda: self.engine.monitor.state() == QProcess.ProcessState.NotRunning)
        self.assertEqual(self.engine.monitor.exitCode(),0)
        self.engine.refresh()
        self.wait_for(lambda: all(s["state"] not in ("ACTIVE","DEGRADED") for s in self.engine.snapshot["sensors"]))
        self.overlay.spike(time.time()-60,time.time())
        self.wait_for(lambda: '"events"' in self.dashboard.details.toPlainText())
        self.assertIn("does not prove AI causation", self.dashboard.details.toPlainText())

    def test_sampler_failure_does_not_display_last_value_as_live(self):
        self.engine.metric={"cpuPercent":1.0}; self.engine.last_metric=time.monotonic()
        self.engine.metrics_failed("Sampler stopped")
        self.assertEqual(self.engine.fresh_metric(),{})
        self.overlay.refresh(); self.assertIn("UNKNOWN",self.overlay.cpu.text())

    def test_tripwire_configuration_round_trip_uses_cli_and_never_opens_target(self):
        self.engine.start(); self.dashboard.open_page("Tripwires")
        self.wait_for(lambda: bool(self.engine.snapshot))
        target=Path(self.temp.name)/"never-created"/"private-data"
        self.dashboard.rule_name.setText("Private data")
        self.dashboard.rule_path.setText(str(target))
        self.dashboard.rule_save.click()
        self.wait_for(lambda: len(self.engine.snapshot.get("tripwires",[]))==1)
        self.assertFalse(target.exists())
        self.assertEqual(self.engine.snapshot["sampledAt"],"NEVER")
        self.assertEqual(self.engine.snapshot["findingsCount"],0)
        self.dashboard.list.setCurrentRow(0)
        self.assertEqual(self.dashboard.rule_name.text(),"Private data")
        self.dashboard.rule_enabled.setChecked(False); self.dashboard.rule_save.click()
        self.wait_for(lambda: not self.engine.snapshot["tripwires"][0]["enabled"])
        self.dashboard.list.setCurrentRow(0); self.dashboard.show_row(0)
        self.dashboard.rule_delete.click()
        self.wait_for(lambda: not self.engine.snapshot.get("tripwires"))
        if os.environ.get("TRIPWIRE_DASHBOARD_RENDER_DIR"):
            directory=Path(os.environ["TRIPWIRE_DASHBOARD_RENDER_DIR"]); directory.mkdir(parents=True,exist_ok=True)
            for page in ("Tripwires","Findings"):
                self.dashboard.open_page(page); QTest.qWait(100)
                self.dashboard.grab().save(str(directory/("portable-"+page.lower()+".png")))

if __name__=="__main__": unittest.main()
