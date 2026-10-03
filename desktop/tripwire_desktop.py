"""Windows/Linux desktop. The Swift CLI owns collection, evidence and findings.
No sockets, browser server, remote content, synthetic observations or auto-install.
"""
from __future__ import annotations
import argparse
from collections import deque
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time
from PySide6.QtCore import QObject, QPoint, QRectF, QProcess, QSettings, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QFont, QIcon, QPainter, QPainterPath, QPixmap
from PySide6.QtWidgets import (QApplication, QComboBox, QHBoxLayout, QLabel, QListWidget,
                             QMainWindow, QMenu, QPlainTextEdit, QPushButton, QLineEdit, QFileDialog, QCheckBox, QFormLayout, QStackedWidget, QSplitter, QScrollArea,
                             QSystemTrayIcon, QVBoxLayout, QWidget)

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "resources" if (ROOT / "resources").is_dir() else ROOT / "Sources" / "TripWireApp" / "Resources"
CYAN, PINK, GREEN = "#0de8ff", "#ff24b0", "#59ffad"
LIMIT = 8 * 1024 * 1024


THEME = """
QMainWindow, QWidget#surface { background:#040b11; color:#d8edf4; }
QWidget { color:#d8edf4; font-family:monospace; font-size:12px; }
QLabel { background:transparent; }
QLabel#wordmark { font-size:31px; font-weight:900; font-style:italic; color:#0de8ff; }
QLabel#tagline { font-size:9px; color:#ff24b0; }
QLabel#eyebrow { color:#82b0be; font-size:10px; }
QLabel#pageTitle { font-size:26px; font-weight:bold; color:#d8edf4; }
QLabel#status { padding:12px; background:#081b24; border-left:2px solid #0de8ff; color:#a6c8d2; }
QLabel#alert { padding:12px; color:#ff59bf; background:#261023; border:1px solid #a63077; }
QPushButton, QComboBox { padding:8px 12px; color:#0de8ff; background:#08202b; border:1px solid #1a5865; border-radius:3px; }
QPushButton:hover { background:#103746; border-color:#0de8ff; }
QPushButton:pressed { background:#174656; }
QPushButton:disabled { color:#52717b; border-color:#183139; }
QPushButton#metric { text-align:left; font-size:16px; padding:14px; border-bottom:2px solid #ba2687; }
QListWidget { background:#06141e; border:1px solid #173d4b; padding:5px; }
QListWidget::item { padding:12px 8px; border-bottom:1px solid #102936; }
QListWidget::item:selected { color:#0de8ff; background:#10303e; border-left:2px solid #ff24b0; }
QListWidget#nav { background:transparent; border:0; font-size:11px; }
QPlainTextEdit, QLineEdit { background:#06141e; color:#d8edf4; border:1px solid #1a4858; padding:10px; selection-background-color:#245867; }
QLineEdit:focus { border-color:#0de8ff; }
QWidget#sidebar { background:#050f18; border-right:1px solid #165161; }
QScrollArea { background:transparent; border:0; }
QSplitter::handle { background:#143541; width:1px; }
QScrollBar:vertical { background:#06141e; width:8px; }
QScrollBar::handle:vertical { background:#245565; min-height:24px; }
QMenu { background:#081b24; border:1px solid #1a5865; }
QMenu::item:selected { background:#174656; }
"""

class CyberSurface(QWidget):
    def paintEvent(self, event):
        painter = QPainter(self); painter.fillRect(self.rect(), QColor("#040b11"))
        painter.setPen(QColor(13,232,255,10))
        for x in range(0,self.width(),32): painter.drawLine(x,0,x,self.height())
        for y in range(0,self.height(),32): painter.drawLine(0,y,self.width(),y)


def record_key(row):
    return row.get("id") or row.get("descriptor",{}).get("id")


def describe_record(row):
    if "descriptor" in row:
        source = row["descriptor"]
        next_step = ("This adapter is not implemented on this platform. Starting monitoring or granting administrator access cannot enable it."
                     if row.get("visibility") == "UNAVAILABLE" else
                     "Use Start monitoring for repeated checks. The limitations below still apply."
                     if row.get("state") == "STOPPED" else
                     "Review the source detail below. A reporting source still observes only its stated scope; this is not a safety verdict.")
        sections = [(source["name"],row.get("state","UNKNOWN")+" · "+row.get("visibility","UNKNOWN")),
                    ("CURRENT STATUS",row.get("detail","UNKNOWN")),("WHAT IT CHECKS",source.get("monitors","UNKNOWN")),
                    ("SOURCE",source.get("source","UNKNOWN")),("NEXT STEP",next_step),("LIMITATIONS","\n".join(source.get("limitations",[])))]
    else:
        observation = row.get("observation",{})
        sections = [("WHAT WAS OBSERVED",observation.get("component","UNKNOWN")),
                    ("SOURCE",row.get("collector",row.get("sourceCollector","UNKNOWN"))),
                    ("OBSERVATION CONFIDENCE",observation.get("confidence","UNKNOWN")),
                    ("METADATA","\n".join(f"{k}: {v}" for k,v in observation.get("attributes",{}).items())),
                    ("BASELINE STATUS",row.get("baselineStatus","UNKNOWN")),
                    ("LIMITATIONS","\n".join(observation.get("limitations",[])+row.get("limitations",[]))),
                    ("INTERPRETATION","This records a scoped observation, not malicious intent or a verified AI instruction. Inventory records show last observed state; they are not a continuous event audit.")]
        for key,label in [("firstSeen","FIRST OBSERVED"),("lastSeen","LAST OBSERVED"),("timestamp","OBSERVATION TIME")]:
            if key in row: sections.append((label,datetime.fromtimestamp(row[key]/1000,timezone.utc).isoformat()))
        if "previousState" in row: sections.append(("BEFORE",json.dumps(row["previousState"],ensure_ascii=False,indent=2)))
        if "currentState" in row: sections.append(("AFTER",json.dumps(row["currentState"],ensure_ascii=False,indent=2)))
    return "\n\n".join(f"{label}\n{value}" for label,value in sections)


def button(text, action, parent=None):
    widget = QPushButton(text, parent)
    widget.clicked.connect(action)
    widget.setCursor(Qt.CursorShape.PointingHandCursor)
    return widget


class Engine(QObject):
    changed = Signal()
    detail_ready = Signal(str, str)
    config_done = Signal(bool, str)
    def __init__(self, executable: Path, database: Path | None):
        super().__init__()
        self.executable, self.database = str(executable.resolve()), database
        self.snapshot, self.metric, self.history = {}, {}, deque(maxlen=64)
        self.error, self.metric_error, self.last_metric = "Waiting for evidence store", "Measuring first interval", 0.0
        self.reader, self.monitor, self.metrics = QProcess(self), QProcess(self), QProcess(self)
        self.reader_buffer, self.metric_buffer = bytearray(), bytearray()
        self.reader.readyReadStandardOutput.connect(self.read_snapshot)
        self.reader.finished.connect(self.snapshot_finished)
        self.reader.errorOccurred.connect(lambda _: self.failed("Evidence reader unavailable"))
        self.metrics.readyReadStandardOutput.connect(self.read_metrics)
        self.metrics.finished.connect(lambda *_: self.metrics_failed("Resource sampler stopped"))
        self.metrics.errorOccurred.connect(lambda _: self.metrics_failed("Resource sampler unavailable"))
        self.monitor.readyReadStandardOutput.connect(lambda: self.monitor.readAllStandardOutput())
        self.monitor.readyReadStandardError.connect(lambda: self.failed(bytes(self.monitor.readAllStandardError()).decode("utf-8", "replace")[:1200]))
        self.monitor.finished.connect(lambda *_: self.changed.emit())
        self.monitor.errorOccurred.connect(lambda _: self.failed("Monitoring process could not start"))
        self.poll = QTimer(self); self.poll.setInterval(2000); self.poll.timeout.connect(self.refresh)
        self.deadline = QTimer(self); self.deadline.setSingleShot(True); self.deadline.setInterval(8000)
        self.deadline.timeout.connect(self.reader_timeout)
        self.started_metrics = False
        self.detail = QProcess(self); self.detail_buffer = bytearray(); self.detail_key = ""
        self.detail.readyReadStandardOutput.connect(self.read_detail)
        self.detail.finished.connect(self.detail_finished)
        self.detail.errorOccurred.connect(lambda _: self.detail_ready.emit(self.detail_key,"Evidence unavailable: reader could not start"))
        self.detail_deadline = QTimer(self); self.detail_deadline.setSingleShot(True); self.detail_deadline.setInterval(8000)
        self.detail_deadline.timeout.connect(self.detail.kill)
        self.config = QProcess(self); self.config_buffer = bytearray()
        self.config.readyReadStandardOutput.connect(self.read_config)
        self.config.readyReadStandardError.connect(self.read_config)
        self.config.finished.connect(self.config_finished)
        self.config.errorOccurred.connect(lambda _: self.config_done.emit(False,"Configuration writer could not start"))
        self.config_deadline = QTimer(self); self.config_deadline.setSingleShot(True); self.config_deadline.setInterval(8000)
        self.config_deadline.timeout.connect(self.config.kill)

    def configure_rule(self, arguments):
        if self.config.state() != QProcess.ProcessState.NotRunning: return
        self.config_buffer.clear()
        self.config.start(self.executable,self.arguments(["tripwires"]+arguments)); self.config_deadline.start()
    def read_config(self):
        self.config_buffer.extend(bytes(self.config.readAllStandardOutput())+bytes(self.config.readAllStandardError()))
        if len(self.config_buffer)>65536: self.config.kill(); self.config_buffer.clear()
    def config_finished(self, code, _status):
        self.config_deadline.stop(); self.read_config()
        self.config_done.emit(code==0,bytes(self.config_buffer).decode("utf-8","replace")[:2000] or "Configuration writer failed or timed out")
        if code==0: self.refresh()

    def arguments(self, values):
        return list(values) + (["--db", str(self.database)] if self.database else [])

    def load_detail(self, key, arguments):
        if self.detail.state() != QProcess.ProcessState.NotRunning:
            self.detail.kill(); self.detail.waitForFinished(1000)
        self.detail_key = key; self.detail_buffer.clear()
        self.detail.start(self.executable,self.arguments(arguments)); self.detail_deadline.start()

    def read_detail(self):
        self.detail_buffer.extend(bytes(self.detail.readAllStandardOutput()))
        if len(self.detail_buffer) > LIMIT:
            self.detail.kill(); self.detail_buffer.clear()

    def detail_finished(self, code, _status):
        self.detail_deadline.stop(); self.read_detail()
        value = bytes(self.detail_buffer).decode("utf-8","replace") if code == 0 else "Evidence unavailable: reader failed, timed out or exceeded the display limit"
        self.detail_ready.emit(self.detail_key,value)

    def start(self):
        self.refresh(); self.poll.start()

    def start_metrics(self):
        if self.metrics.state() == QProcess.ProcessState.NotRunning:
            self.metric_buffer.clear(); self.metric_error = "Measuring first interval"
            self.started_metrics = True
            self.metrics.start(self.executable, ["metrics"])

    def refresh(self):
        if self.reader.state() != QProcess.ProcessState.NotRunning:
            return
        self.reader_buffer.clear(); self.reader.start(self.executable, self.arguments(["view", "--json"]))
        self.deadline.start()

    def read_snapshot(self):
        self.reader_buffer.extend(bytes(self.reader.readAllStandardOutput()))
        if len(self.reader_buffer) > LIMIT:
            self.reader.kill(); self.reader_buffer.clear(); self.failed("Evidence response exceeded its display bound")

    def snapshot_finished(self, code, _status):
        self.deadline.stop()
        self.read_snapshot()
        try:
            if code != 0:
                raise ValueError(bytes(self.reader.readAllStandardError()).decode("utf-8", "replace")[:1200] or "Evidence reader failed")
            value = json.loads(self.reader_buffer)
            if value.get("schemaVersion") != 1:
                raise ValueError("Unsupported evidence interface version")
            self.snapshot, self.error = value, ""
        except (ValueError, TypeError) as exc:
            self.error = str(exc)
        self.changed.emit()

    def reader_timeout(self):
        self.reader.kill(); self.failed("Evidence reader timed out; displayed records may be stale")

    def read_metrics(self):
        self.metric_buffer.extend(bytes(self.metrics.readAllStandardOutput()))
        if len(self.metric_buffer) > 65536:
            self.metrics.kill(); self.metric_buffer.clear(); self.metrics_failed("Oversized metrics response"); return
        while b"\n" in self.metric_buffer:
            line, _, self.metric_buffer = self.metric_buffer.partition(b"\n")
            try:
                value = json.loads(line)
                if value.get("schemaVersion") != 1:
                    raise ValueError()
                stamp = datetime.fromisoformat(value["timestamp"].replace("Z", "+00:00")).timestamp()
                self.metric, self.last_metric, self.metric_error = value, time.monotonic(), ""
                self.history.append((stamp, value.get("cpuPercent")))
            except (ValueError, KeyError, TypeError):
                self.metric_error = "Invalid metrics response; sample unavailable"
        self.changed.emit()

    def failed(self, text):
        self.error = text; self.changed.emit()

    def metrics_failed(self, text):
        self.metric_error = text; self.last_metric = 0; self.changed.emit()

    def fresh_metric(self):
        return self.metric if self.last_metric and time.monotonic() - self.last_metric <= 3 and not self.metric_error else {}

    def toggle_monitor(self):
        if self.monitor.state() == QProcess.ProcessState.NotRunning:
            self.monitor.start(self.executable, self.arguments(["monitor", "5", "--control-stdin"]))
        else:
            self.monitor.write(b"stop\n")
        self.changed.emit()

    def shutdown(self):
        self.poll.stop(); self.deadline.stop(); self.detail_deadline.stop(); self.config_deadline.stop()
        if self.monitor.state() != QProcess.ProcessState.NotRunning: self.monitor.write(b"stop\n")
        if self.monitor.state() != QProcess.ProcessState.NotRunning and not self.monitor.waitForFinished(3000):
            # Only our own collector child; restart records any ungraceful stop as a gap.
            self.monitor.kill(); self.monitor.waitForFinished(1000)
        for process in (self.reader, self.metrics, self.detail, self.config):
            if process.state() != QProcess.ProcessState.NotRunning:
                process.terminate()
                if not process.waitForFinished(1000): process.kill(); process.waitForFinished(1000)


class CPUChart(QWidget):
    selected = Signal(float, float)
    def __init__(self, engine, parent=None):
        super().__init__(parent); self.engine = engine; self.start_x = None; self.frozen = None
        self.setMinimumHeight(14); self.setCursor(Qt.CursorShape.CrossCursor)
        self.setToolTip("Host CPU, 0–100%, last 60 seconds. Click or drag to inspect. Gaps are unknown intervals.")
    def paintEvent(self, _event):
        painter = QPainter(self); painter.fillRect(self.rect(), QColor(0, 10, 14, 170))
        now, history = self.frozen or (time.time(), list(self.engine.history))
        painter.setPen(QColor("#174044"))
        for i in range(1, 6): painter.drawLine(int(self.width()*i/6), 0, int(self.width()*i/6), self.height())
        path, previous = QPainterPath(), None
        for stamp, value in history:
            if stamp < now - 60 or stamp > now or value is None:
                previous = None; continue
            x, y = self.width()*(stamp-now+60)/60, self.height()*(1-max(0,min(100,value))/100)
            if previous is None or stamp - previous > 3: path.moveTo(x,y)
            else: path.lineTo(x,y)
            previous = stamp
        painter.setPen(QColor(GREEN)); painter.drawPath(path)
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.start_x = event.position().x(); self.frozen = (time.time(), list(self.engine.history)); self.update()
    def mouseReleaseEvent(self, event):
        if self.start_x is None: return
        now = self.frozen[0]
        a, b = sorted((self.start_x, event.position().x()))
        start, end = [now - 60 + max(0,min(self.width(),x))/max(1,self.width())*60 for x in (a,b)]
        if end-start < 1: start -= 2; end += 2
        self.start_x = None; self.frozen = None; self.selected.emit(start,end)


class Dashboard(QMainWindow):
    def __init__(self, engine):
        super().__init__(); self.engine = engine; self.page = "Findings"; self.rows = []; self.selection = None
        self.setWindowTitle("TripWire — RedMars"); self.resize(1240,820); self.setMinimumSize(960,620); self.setStyleSheet(THEME)
        self.dismissed_alerts=set(); self.active_alert=None; self.editing_rule=None
        root=CyberSurface(); root.setObjectName("surface"); self.setCentralWidget(root)
        outer=QHBoxLayout(root); outer.setContentsMargins(0,0,0,0); outer.setSpacing(0)
        sidebar=QWidget(); sidebar.setObjectName("sidebar"); sidebar.setFixedWidth(205); side=QVBoxLayout(sidebar); side.setContentsMargins(16,24,12,16)
        brand=QLabel("TripWire"); brand.setObjectName("wordmark"); side.addWidget(brand)
        tagline=QLabel("YOUR CYBER WATCHDOG"); tagline.setObjectName("tagline"); side.addWidget(tagline); side.addSpacing(26)
        self.nav=QListWidget(); self.nav.setObjectName("nav"); side.addWidget(self.nav)
        self.pages=QComboBox(); self.pages.addItems(["Findings","Tripwire alerts","Tripwires","Files","Processes","Network","Kernel / extensions","Checks","Recent evidence"]); self.pages.hide()
        self.nav.addItems([self.pages.itemText(i) for i in range(self.pages.count())]); self.nav.setCurrentRow(0)
        self.nav.currentTextChanged.connect(self.pages.setCurrentText)
        self.pages.currentTextChanged.connect(self.select_page)
        side.addWidget(QLabel("LOCAL BY DESIGN")); credit=QLabel("RedMars LLC · MIT licensed"); credit.setObjectName("eyebrow"); side.addWidget(credit); outer.addWidget(sidebar)
        body=QWidget(); layout=QVBoxLayout(body); layout.setContentsMargins(26,24,26,18); layout.setSpacing(16); outer.addWidget(body,1)
        eyebrow=QLabel("OBSERVATION CONSOLE / LOCAL EVIDENCE"); eyebrow.setObjectName("eyebrow"); layout.addWidget(eyebrow)
        toolbar=QHBoxLayout(); layout.addLayout(toolbar)
        self.title=QLabel("Findings"); self.title.setObjectName("pageTitle"); toolbar.addWidget(self.title); toolbar.addStretch()
        self.monitor_button=button("Start monitoring",engine.toggle_monitor); toolbar.addWidget(self.monitor_button)
        self.overlay_button=button("Overlay ↗",lambda:None); toolbar.addWidget(self.overlay_button)
        subtitle=QLabel("Your machine. Your boundaries. Evidence you can inspect."); subtitle.setObjectName("eyebrow"); layout.addWidget(subtitle)
        metrics=QHBoxLayout(); layout.addLayout(metrics)
        self.findings_metric=button("—\nRecorded findings ↗",lambda:self.open_page("Findings")); self.rules_metric=button("—\nEnabled tripwires ↗",lambda:self.open_page("Tripwires")); self.checks_metric=button("—\nReporting checks ↗",lambda:self.open_page("Checks"))
        for widget in (self.findings_metric,self.rules_metric,self.checks_metric): widget.setObjectName("metric"); metrics.addWidget(widget,1)
        self.status=QLabel(); self.status.setObjectName("status"); self.status.setTextFormat(Qt.TextFormat.PlainText); self.status.setWordWrap(True); layout.addWidget(self.status)
        self.alert_box=QWidget(); alerts=QHBoxLayout(self.alert_box); alerts.setContentsMargins(0,0,0,0)
        self.alert_label=QLabel(); self.alert_label.setObjectName("alert"); self.alert_label.setTextFormat(Qt.TextFormat.PlainText); self.alert_label.setWordWrap(True); alerts.addWidget(self.alert_label,1)
        alerts.addWidget(button("Inspect alert ↗",self.inspect_alert)); alerts.addWidget(button("Dismiss",self.dismiss_alert)); self.alert_box.hide(); layout.addWidget(self.alert_box)
        self.content=QSplitter(); layout.addWidget(self.content,1)
        self.list=QListWidget(); self.list.currentRowChanged.connect(self.show_row); self.content.addWidget(self.list)
        self.detail_stack=QStackedWidget(); self.content.addWidget(self.detail_stack)
        self.details=QPlainTextEdit(); self.details.setReadOnly(True); self.detail_stack.addWidget(self.details)
        self.config_panel=self.make_config_panel(); self.config_scroll=QScrollArea(); self.config_scroll.setWidgetResizable(True); self.config_scroll.setWidget(self.config_panel); self.detail_stack.addWidget(self.config_scroll); self.content.setSizes([330,600])
        note=QLabel("Metadata only · Alerting, not blocking · Snapshots can miss brief access · AI intent remains unknown"); note.setObjectName("eyebrow"); note.setWordWrap(True); layout.addWidget(note)
        engine.changed.connect(self.refresh); engine.config_done.connect(self.config_finished)
        self.detail_key,self.detail_prefix,self.inspection="","",False
        engine.detail_ready.connect(self.show_detail)
    def make_config_panel(self):
        widget=QWidget(); form=QVBoxLayout(widget); form.setContentsMargins(20,0,0,0)
        heading=QLabel("SET THE BOUNDARIES"); heading.setObjectName("tagline"); form.addWidget(heading)
        form.addWidget(button("+ New tripwire",self.new_rule))
        fields=QFormLayout(); form.addLayout(fields)
        self.rule_name=QLineEdit(); self.rule_name.setPlaceholderText("Private credentials"); fields.addRow("Name",self.rule_name)
        self.rule_kind=QComboBox(); self.rule_kind.addItems(["folder","file","application"]); fields.addRow("Boundary",self.rule_kind)
        self.rule_path=QLineEdit(); self.rule_path.setPlaceholderText("Absolute target path"); fields.addRow("Path",self.rule_path)
        form.addWidget(button("Choose path…",self.choose_rule_path))
        self.rule_enabled=QCheckBox("Enabled for future observations"); self.rule_enabled.setChecked(True); form.addWidget(self.rule_enabled)
        actions=QHBoxLayout(); form.addLayout(actions)
        self.rule_save=button("Save tripwire",self.save_rule); actions.addWidget(self.rule_save)
        self.rule_delete=button("Delete",self.delete_rule); self.rule_delete.setEnabled(False); actions.addWidget(self.rule_delete)
        self.config_status=QLabel("Choose a boundary and save. No target is opened or modified."); self.config_status.setWordWrap(True); self.config_status.setTextFormat(Qt.TextFormat.PlainText); form.addWidget(self.config_status)
        self.rule_coverage=QLabel(); self.rule_coverage.setWordWrap(True); self.rule_coverage.setTextFormat(Qt.TextFormat.PlainText); form.addWidget(self.rule_coverage)
        note=QLabel("AI-associated activity only. File/folder rules match regular open-file snapshots. Applications also match sampled AI process ancestry. Brief access, aliases, detached launches and unrecognized agents may be missed. Windows file monitoring is unavailable. Saving does not start monitoring; editing or re-enabling starts a new alert cycle on the next match."); note.setWordWrap(True); note.setObjectName("eyebrow"); form.addWidget(note); form.addStretch()
        return widget
    def new_rule(self):
        self.editing_rule=None; self.rule_name.clear(); self.rule_path.clear(); self.rule_kind.setCurrentText("folder"); self.rule_enabled.setChecked(True); self.rule_delete.setEnabled(False)
        self.config_status.setText("New boundary · no target is opened or modified")
    def choose_rule_path(self):
        kind=self.rule_kind.currentText()
        if kind=="folder": value=QFileDialog.getExistingDirectory(self,"Choose tripwire folder")
        else: value,_=QFileDialog.getOpenFileName(self,"Choose application executable" if kind=="application" else "Choose tripwire file")
        if value:
            self.rule_path.setText(value)
            if not self.rule_name.text(): self.rule_name.setText(Path(value).name)
    def save_rule(self):
        args=["save","--name",self.rule_name.text(),"--path",self.rule_path.text(),"--kind",self.rule_kind.currentText()]
        if self.editing_rule: args.extend(["--id",self.editing_rule])
        if not self.rule_enabled.isChecked(): args.append("--disabled")
        self.rule_save.setEnabled(False); self.rule_delete.setEnabled(False); self.engine.configure_rule(args)
    def delete_rule(self):
        if self.editing_rule:
            self.rule_save.setEnabled(False); self.rule_delete.setEnabled(False); self.engine.configure_rule(["delete",self.editing_rule])
    def config_finished(self, success, message):
        self.rule_save.setEnabled(True); self.rule_delete.setEnabled(bool(self.editing_rule)); self.config_status.setText(message)
        if success: self.new_rule(); self.config_status.setText(message)
    def inspect_alert(self):
        if not self.active_alert: return
        self.open_page("Findings")
        index=next((i for i,r in enumerate(self.rows) if r.get("id")==self.active_alert["id"]),-1)
        self.list.setCurrentRow(index)
    def dismiss_alert(self):
        if self.active_alert: self.dismissed_alerts.add(self.active_alert["id"])
        self.refresh()
    def show_detail(self, key, text):
        if key != self.detail_key: return
        if key.startswith("spike:"):
            try: text = json.dumps(json.loads(text),ensure_ascii=False,indent=2)
            except ValueError: pass
        self.details.setPlainText(self.detail_prefix+text)
    def select_page(self, page):
        self.title.setText("Tripwires / configuration" if page=="Tripwires" else page)
        self.nav.blockSignals(True); self.nav.setCurrentRow(self.pages.findText(page)); self.nav.blockSignals(False)
        self.detail_stack.setCurrentIndex(1 if page=="Tripwires" else 0)
        self.page = page; self.selection = None; self.detail_key = ""; self.inspection = False; self.rows = []; self.refresh()
    def open_page(self, page="Findings"):
        self.pages.setCurrentText(page); self.showNormal(); self.raise_(); self.activateWindow()
    def refresh(self):
        s = self.engine.snapshot
        self.status.setText(self.engine.error or f"{s.get('platform','')} · {s.get('coverage','UNKNOWN')} · Last completed check: {s.get('sampledAt','NEVER')}")
        self.monitor_button.setText("Stop monitoring" if self.engine.monitor.state() != QProcess.ProcessState.NotRunning else "Start monitoring")
        self.status.setToolTip("CPU/RAM sampling is independent of security monitoring. Missing adapters are listed under Checks.")
        rules=s.get("tripwires",[])
        self.findings_metric.setText(f"{s.get('findingsCount','—')}\nRecorded findings ↗")
        self.rules_metric.setText(f"{sum(r.get('enabled',False) for r in rules) if s else '—'}\nEnabled tripwires ↗")
        live=sum(x.get("state") in ("ACTIVE","DEGRADED") and x.get("visibility") in ("OBSERVABLE","LIMITED") for x in s.get("sensors",[]))
        self.checks_metric.setText(f"{live if s and not self.engine.error else '—'}\nReporting checks ↗")
        self.active_alert=next((f for f in s.get("findings",[]) if f.get("ruleID","").startswith("user-tripwire:") and f["id"] not in self.dismissed_alerts),None)
        self.alert_box.setVisible(bool(self.active_alert))
        if self.active_alert: self.alert_label.setText(self.active_alert["title"]+"\n"+self.active_alert["component"]+(" · retained evidence; reader unavailable" if self.engine.error else ""))
        source=next((x for x in s.get("sensors",[]) if x.get("descriptor",{}).get("id")=="ai-open-files"),{})
        process_source=next((x for x in s.get("sensors",[]) if x.get("descriptor",{}).get("id")=="processes"),{})
        self.rule_coverage.setText("FILE SOURCE: "+source.get("state","UNKNOWN")+" / "+source.get("visibility","UNKNOWN")+"\nPROCESS SOURCE: "+process_source.get("state","UNKNOWN")+" / "+process_source.get("visibility","UNKNOWN")+"\nReview Checks for coverage and next steps.")
        if self.page == "Tripwires": rows = rules
        elif self.page == "Tripwire alerts": rows = [f for f in s.get("findings",[]) if f.get("ruleID","").startswith("user-tripwire:")]
        elif self.page == "Findings": rows = s.get("findings",[])
        elif self.page == "Checks": rows = s.get("sensors",[])
        elif self.page == "Recent evidence": rows = s.get("events",[])
        else:
            classes = {"Files":{"FILE"},"Processes":{"EXEC"},"Network":{"NET","PORT"},"Kernel / extensions":{"EXT"}}
            rows = [r for r in s.get("inventory",[]) if r.get("observation",{}).get("eventClass") in classes.get(self.page,set())]
        if s.get("inventoryTruncated") or s.get("findingsTruncated"):
            self.status.setText(self.status.text()+" · Display limited to 1,000 records; use CLI filters for remaining evidence")
        if rows == self.rows: return
        self.rows = rows; self.list.blockSignals(True); self.list.clear()
        for row in rows:
            title = row.get("name") or row.get("title") or row.get("descriptor",{}).get("name") or row.get("observation",{}).get("component","Unknown")
            if "state" in row: title += " · " + row["state"]
            if "enabled" in row: title += " · " + ("ENABLED" if row["enabled"] else "DISABLED")
            self.list.addItem(title)
        index = next((i for i,r in enumerate(rows) if self.selection is not None and record_key(r) == self.selection), -1)
        if not rows and self.page=="Tripwires": self.list.addItem("No tripwires yet.\nCreate your first boundary →")
        self.list.setCurrentRow(index); self.list.blockSignals(False)
        if self.inspection: return
        if index >= 0: self.show_row(index)
        elif not rows:
            self.details.setPlainText("No stored records in this display scope. This does not establish absence or safety.\n\nCheck source availability and permissions under Checks.")
        else: self.details.setPlainText("Select a record to inspect what was observed, why it was flagged and the source limitations.")
    def show_row(self, index):
        if not 0 <= index < len(self.rows): return
        self.inspection = False
        row = self.rows[index]; self.selection = record_key(row); self.detail_key = ""
        if self.page=="Tripwires":
            self.editing_rule=row["id"]; self.rule_name.setText(row["name"]); self.rule_path.setText(row["path"]); self.rule_kind.setCurrentText(row["kind"]); self.rule_enabled.setChecked(row["enabled"]); self.rule_delete.setEnabled(True)
            self.config_status.setText("Editing this boundary. Existing evidence is retained."); return
        if "whyFlagged" in row:
            sections = [("WHAT WAS FOUND",row["whatHappened"]),("WHY FLAGGED",row["whyFlagged"]),("BASELINE",row["baselineDifference"]),("INTENT",row.get("intent","UNKNOWN")),("LIMITATIONS","\n".join(row.get("limitations",[]))),("NEXT STEPS","\n".join(row.get("suggestedInvestigation",[])))]
            self.details.setPlainText("\n\n".join(f"{a}\n{b}" for a,b in sections) + "\n\nEvidence IDs: " + ", ".join(row.get("eventIDs",[])))
            self.detail_key, self.detail_prefix = row["id"], ""
            self.engine.load_detail(self.detail_key,["explain",row["id"]])
        else: self.details.setPlainText(describe_record(row))
    def inspect_spike(self, start, end):
        self.showNormal(); self.raise_(); self.activateWindow()
        values = [(stamp,value) for stamp,value in self.engine.history if start <= stamp <= end]
        self.inspection = True
        self.detail_key = f"spike:{start}:{end}"
        self.detail_prefix = ("HOST CPU INVESTIGATION\n" + datetime.fromtimestamp(start,timezone.utc).isoformat() + " → " + datetime.fromtimestamp(end,timezone.utc).isoformat() +
            "\n\nMEASUREMENTS\n" + "\n".join(f"{datetime.fromtimestamp(t,timezone.utc).isoformat()}: {v if v is not None else 'UNKNOWN'}%" for t,v in values) +
            "\n\nSTORED EVIDENCE IN THIS WINDOW\nTime proximity does not prove AI causation. A missing record does not establish that nothing happened. Results are bounded; inspect truncation flags.\n\n")
        self.details.setPlainText(self.detail_prefix+"Loading…")
        iso = lambda t: datetime.fromtimestamp(t,timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.engine.load_detail(self.detail_key,["investigate",iso(start),iso(end),"--json"])



class Overlay(QWidget):
    LAYOUTS = {"Super compact": ("OverlayFrameMini.png",300,440,(62/360,136/331.1,214/360,153/331.1)),
               "Horizontal": ("OverlayFrame.png",480,1000,(.118,.438,.768,.385)),
               "Vertical": ("OverlayFrameVertical.png",260,340,(69/360,245/1080,190/360,694/1080))}
    def __init__(self, engine, dashboard):
        super().__init__(None, Qt.WindowType.Tool | Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.engine, self.dashboard, self.expanded = engine,dashboard,False
        self.settings = QSettings("TripWire","PortableDesktop")
        self.mode = self.settings.value("layout","Super compact")
        if self.mode not in self.LAYOUTS: self.mode = "Super compact"
        self.setWindowTitle("TripWire Watchdog"); self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.well = QWidget(self); self.well.setObjectName("well")
        layout = QVBoxLayout(self.well); layout.setContentsMargins(2,1,2,1); layout.setSpacing(2)
        bar = QHBoxLayout(); layout.addLayout(bar)
        self.chooser = QComboBox(); self.chooser.addItems(list(self.LAYOUTS)); self.chooser.setCurrentText(self.mode); self.chooser.currentTextChanged.connect(self.change_layout); bar.addWidget(self.chooser)
        self.shrink = button("Shrink", self.shrink_now); bar.addWidget(self.shrink)
        self.count = button("Findings: —",lambda:self.inspect("Tripwire alerts" if any(f.get("ruleID","").startswith("user-tripwire:") for f in self.engine.snapshot.get("findings",[])) else "Findings")); layout.addWidget(self.count)
        self.cpu = button("CPU UNKNOWN",lambda: self.spike(time.time()-60,time.time())); layout.addWidget(self.cpu)
        self.chart = CPUChart(engine); self.chart.selected.connect(self.spike); layout.addWidget(self.chart)
        self.memory = button("RAM UNKNOWN",self.memory_details); layout.addWidget(self.memory)
        self.checks = button("Checks UNKNOWN",lambda:self.inspect("Checks")); layout.addWidget(self.checks)
        links = QHBoxLayout(); layout.addLayout(links); links.addWidget(button("Files ↗",lambda:self.inspect("Files"))); links.addWidget(button("Dashboard ↗",lambda:self.inspect("Findings")))
        self.expand = button("□",self.expand_now,self); self.minimize = button("−",self.showMinimized,self); self.close_button = button("×",self.hide,self)
        self.expand.setToolTip("Expand overlay"); self.close_button.setToolTip("Close overlay; sampling continues while TripWire is open")
        self.timer = QTimer(self); self.timer.setInterval(1000); self.timer.timeout.connect(self.refresh); self.timer.start()
        engine.changed.connect(self.refresh); self.configure()
    def configure(self):
        filename,small,large,_ = self.LAYOUTS[self.mode]
        self.art = QPixmap(str(ART/filename))
        if self.art.isNull(): raise RuntimeError(f"Missing overlay artwork: {filename}")
        screen = self.screen().availableGeometry(); width = min(large if self.expanded else small,screen.width(),int(screen.height()*self.art.width()/self.art.height()))
        self.setFixedSize(width,round(width*self.art.height()/self.art.width()))
        self.shrink.setVisible(self.expanded)
        self.settings.setValue("layout",self.mode); self.position_children(); self.fit(); self.update()
    def change_layout(self, value):
        self.mode = value; self.expanded = False; self.configure()
    def expand_now(self): self.expanded = True; self.configure()
    def shrink_now(self): self.expanded = False; self.configure()
    def position_children(self):
        x,y,w,h = self.LAYOUTS[self.mode][3]
        self.well.setGeometry(round(x*self.width()),round(y*self.height()),round(w*self.width()),round(h*self.height()))
        self.well.setStyleSheet(f"QWidget#well {{background:rgba(1,12,20,222);}} QPushButton,QComboBox {{font: {min(14,max(9,round(self.width()/40)))}px monospace; padding:0; border:0; color:{CYAN};background:transparent;}}")
        # Painted controls use explicit hit areas; vertical art needs drawn controls.
        if self.mode == "Super compact": positions = [(.65,.20),(.70,.20),(.755,.20)]
        elif self.mode == "Horizontal": positions = [(.846,.12),(.889,.12),(.932,.12)]
        else: positions = [(.55,.17),(.66,.17),(.77,.17)]
        for control,(x,y) in zip((self.minimize,self.expand,self.close_button),positions):
            control.setAccessibleName(control.toolTip() or "Minimize overlay")
            control.setText(("×" if control is self.close_button else "□" if control is self.expand else "−") if self.mode == "Vertical" else "")
            control.setGeometry(round(x*self.width()),round(y*self.height()),max(18,round(.05*self.width())),20)
            control.setStyleSheet(f"color:{PINK if control is self.close_button else CYAN};background:transparent;border:0;font:16px monospace")
    def fit(self):
        if QApplication.platformName().startswith("wayland"):
            self.setToolTip("Drag the logo. Wayland controls window placement; exact edge positioning depends on your desktop.")
            return
        area = self.screen().availableGeometry()
        outlines = {"Super compact":(64/1308,189/1203,1143/1308,1177/1203),"Horizontal":(34/1671,82/941,1635/1671,859/941),"Vertical":(23/724,74/2172,676/724,2024/2172)}
        left,top,right,bottom=outlines[self.mode]
        self.move(round(max(area.left()-left*self.width(),min(self.x(),area.right()+1-right*self.width()))),round(max(area.top()-top*self.height(),min(self.y(),area.bottom()+1-bottom*self.height()))))
    def paintEvent(self,_event):
        painter = QPainter(self); painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform); painter.drawPixmap(self.rect(),self.art)
    def mousePressEvent(self,event):
        # Native system dragging also works on Wayland, which rejects setPosition.
        if event.button() == Qt.MouseButton.LeftButton and event.position().y() < self.well.y():
            handle = self.windowHandle()
            if handle: handle.startSystemMove()
    def showEvent(self,event):
        self.engine.start_metrics(); self.refresh(); super().showEvent(event)
    def inspect(self,page): self.hide(); self.dashboard.open_page(page)
    def spike(self,start,end): self.hide(); self.dashboard.inspect_spike(start,end)
    def memory_details(self):
        self.inspect("Checks"); m=self.engine.fresh_metric()
        self.dashboard.details.setPlainText("MEMORY\n"+m.get("memoryDefinition","UNKNOWN — no fresh sample")+"\n\nPRESSURE\n"+m.get("pressure","UNKNOWN")+"\n"+m.get("pressureDetail",self.engine.metric_error))
    def refresh(self):
        s,m = self.engine.snapshot,self.engine.fresh_metric()
        hits=[f for f in s.get("findings",[]) if f.get("ruleID","").startswith("user-tripwire:")]
        self.count.setText((f"⚠ {len(hits)} tripwire alerts" if hits else f"{s.get('findingsCount','—')} findings")+(" (stale)" if self.engine.error and s else " ↗"))
        self.count.setToolTip(hits[0]["title"] if hits else "Inspect recorded findings")
        cpu=m.get("cpuPercent"); self.cpu.setText("CPU / HOST  "+(f"{cpu:.1f}%" if cpu is not None else "UNKNOWN"))
        used,total=m.get("memoryUsedBytes"),m.get("memoryTotalBytes")
        self.memory.setText(f"RAM {used/2**30:.1f}/{total/2**30:.0f} GiB ⓘ" if used is not None and total else "RAM UNKNOWN ⓘ")
        self.memory.setToolTip(m.get("memoryDefinition",self.engine.metric_error))
        live=sum(x.get("state") in ("ACTIVE","DEGRADED") for x in s.get("sensors",[]))
        unavailable=sum(x.get("visibility")=="UNAVAILABLE" for x in s.get("sensors",[]))
        failed=sum(x.get("state") in ("ERROR","DATA LOSS DETECTED") for x in s.get("sensors",[]))
        self.checks.setText("Store unavailable ↗" if self.engine.error else f"{live} live · {failed} failed ↗" if failed else f"{live} live · {unavailable} unavailable ↗")
        self.checks.setToolTip(self.engine.error or s.get("coverage","UNKNOWN")); self.chart.update()


def main():
    parser=argparse.ArgumentParser(description="TripWire Windows/Linux desktop")
    parser.add_argument("--cli",required=True,type=Path); parser.add_argument("--db",type=Path)
    args=parser.parse_args()
    executable=args.cli.resolve(strict=True)
    app=QApplication(sys.argv); app.setOrganizationName("TripWire"); app.setApplicationName("TripWireApp")
    app.setStyleSheet(THEME)
    icon=QIcon(str(ART/"AppIcon.png" if (ART/"AppIcon.png").exists() else ROOT/"assets/branding/AppIcon.png")); app.setWindowIcon(icon)
    engine=Engine(executable,args.db); dashboard=Dashboard(engine); overlay=Overlay(engine,dashboard)
    dashboard.overlay_button.clicked.connect(overlay.showNormal)
    tray=QSystemTrayIcon(icon,app); menu=QMenu(); menu.addAction("Overlay",overlay.showNormal); menu.addAction("Dashboard",lambda: dashboard.open_page()); menu.addAction("Quit",app.quit); tray.setContextMenu(menu)
    if QSystemTrayIcon.isSystemTrayAvailable(): tray.show(); app.setQuitOnLastWindowClosed(False)
    app.aboutToQuit.connect(engine.shutdown); engine.start(); dashboard.show(); overlay.show()
    sys.exit(app.exec())

if __name__ == "__main__": main()
