"""Risk review presentation. Counts and corrections come from the Swift store."""
import json
from datetime import datetime, timezone
from html import escape
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPainter, QPainterPath, QLinearGradient
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLCDNumber, QListWidget, QLineEdit, QComboBox, QPlainTextEdit, QScrollArea, QSplitter, QMessageBox)

LEVELS = [("critical", "#ff455e"), ("high", "#ff8538"), ("medium", "#ffc940"), ("low", "#0de8ff"), ("unassessed", "#b0a1d1")]
STATUSES = [("open", "Open"), ("cleared", "Cleared"), ("expected", "Expected activity"), ("false-positive", "False positive")]

class ConsoleHousing(QWidget):
    def paintEvent(self,event):
        painter=QPainter(self); painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w,h=self.width()-1,self.height()-1; shape=QPainterPath(); shape.moveTo(0,16)
        for x,y in [(16,0),(w,0),(w,h-16),(w-16,h),(0,h)]:shape.lineTo(x,y)
        shape.closeSubpath(); fill=QLinearGradient(0,0,0,h); fill.setColorAt(0,QColor("#10232d"));fill.setColorAt(1,QColor("#030a11"))
        painter.fillPath(shape,fill); painter.setPen(QColor("#26717e")); painter.drawPath(shape)
        painter.fillRect(24,0,85,3,QColor("#0de8ff")); painter.fillRect(w-109,0,85,3,QColor("#ff24b0"))
        painter.setPen(QColor("#ff24b0")); painter.drawLine(0,h,w-16,h);painter.drawLine(w-16,h,w,h-16)

class RiskCenter(QWidget):
    def __init__(self, dashboard):
        super().__init__(); self.dashboard=dashboard; self.engine=dashboard.engine
        self.level=None; self.selected=None; self.rows=[]; self.revision=None; self.history=[]; self.saved_assessment=None; self.clearing=False
        outer=QVBoxLayout(self); outer.setContentsMargins(0,0,0,0); outer.setSpacing(14)
        console=ConsoleHousing()
        console.setObjectName("console"); top=QVBoxLayout(console); top.setContentsMargins(18,14,18,12)
        header=QHBoxLayout(); title=QLabel("RISK CONTROL"); title.setStyleSheet("font-size:24px;font-weight:bold;letter-spacing:3px;"); header.addWidget(title)
        header.addStretch(); self.total=QLabel("— OPEN FINDINGS"); self.total.setStyleSheet("color:#0de8ff;font-weight:bold;"); header.addWidget(self.total); top.addLayout(header)
        subtitle=QLabel("PRIORITIZE · INSPECT · CORRECT"); subtitle.setObjectName("eyebrow"); top.addWidget(subtitle)
        modules=QHBoxLayout(); modules.setSpacing(8); top.addLayout(modules); self.counters={}; self.buttons={}
        for level,color in LEVELS:
            module=QWidget(); module.setObjectName("module"); module.setStyleSheet(f"QWidget#module {{background:#040c13;border:1px solid {color};border-top:3px solid {color};}}")
            content=QVBoxLayout(module); content.setContentsMargins(10,10,10,10); content.setSpacing(9)
            label=QLabel("● "+level.upper()); label.setStyleSheet(f"color:{color};font-size:10px;font-weight:bold;"); content.addWidget(label)
            counter=QLCDNumber(); counter.setSegmentStyle(QLCDNumber.SegmentStyle.Flat); counter.setDigitCount(2); counter.display("--"); counter.setMinimumHeight(48)
            counter.setStyleSheet(f"color:{color};background:#02080d;border:0;"); content.addWidget(counter)
            inspect=QPushButton("INSPECT ↗"); inspect.setStyleSheet(f"color:{color};font-size:9px;padding:5px;border:1px solid {color};")
            inspect.clicked.connect(lambda _=False, selected=level:self.filter_level(selected)); content.addWidget(inspect)
            self.counters[level]=counter; self.buttons[level]=inspect; modules.addWidget(module,1)
        footer=QLabel("▰ ▰ ▰   Open findings by current classification · Risk is priority; intent remains unknown."); footer.setWordWrap(True); footer.setObjectName("eyebrow"); top.addWidget(footer); outer.addWidget(console)
        split=QSplitter(); outer.addWidget(split,1)
        queue=QWidget(); q=QVBoxLayout(queue); q.setContentsMargins(0,0,12,0)
        q.addWidget(QLabel("REVIEW QUEUE")); controls=QHBoxLayout(); self.scope=QComboBox(); self.scope.addItems(["Open","Reviewed"]); controls.addWidget(self.scope)
        clear=QPushButton("All levels"); clear.setToolTip("Remove the risk-level filter. Findings are unchanged."); clear.clicked.connect(lambda:self.filter_level(None)); controls.addWidget(clear); q.addLayout(controls)
        self.filter_label=QLabel("ALL LEVELS"); self.filter_label.setObjectName("eyebrow"); q.addWidget(self.filter_label)
        self.search=QLineEdit(); self.search.setPlaceholderText("Search findings"); q.addWidget(self.search)
        self.clear_queue=QPushButton("Clear queue…"); self.clear_queue.clicked.connect(self.confirm_clear_queue); q.addWidget(self.clear_queue)
        self.clear_result=QLabel(); self.clear_result.setWordWrap(True); self.clear_result.setTextFormat(Qt.TextFormat.PlainText); q.addWidget(self.clear_result)
        self.queue=QListWidget(); q.addWidget(self.queue,1); self.scope.currentTextChanged.connect(self.refresh); self.search.textChanged.connect(self.refresh); self.queue.currentRowChanged.connect(self.select)
        self.queue_note=QLabel(); self.queue_note.setWordWrap(True); self.queue_note.setObjectName("eyebrow"); q.addWidget(self.queue_note); split.addWidget(queue)
        scroll=QScrollArea(); scroll.setWidgetResizable(True); split.addWidget(scroll)
        self.panel=QWidget(); self.panel.setObjectName("surface"); scroll.setWidget(self.panel); detail=QVBoxLayout(self.panel); detail.setContentsMargins(18,14,18,14)
        self.heading=QLabel("Select a finding"); self.heading.setTextFormat(Qt.TextFormat.PlainText); self.heading.setWordWrap(True); self.heading.setStyleSheet("font-size:18px;font-weight:bold;"); detail.addWidget(self.heading)
        self.badge=QLabel(); self.badge.setTextFormat(Qt.TextFormat.PlainText); self.badge.setWordWrap(True); detail.addWidget(self.badge)
        self.editor=QWidget(); edit=QVBoxLayout(self.editor); edit.setContentsMargins(0,12,0,12)
        label=QLabel("CORRECT CLASSIFICATION"); label.setStyleSheet("color:#ff24b0;font-weight:bold;"); edit.addWidget(label)
        self.original=QLabel(); self.original.setWordWrap(True); self.original.setObjectName("eyebrow"); edit.addWidget(self.original)
        selectors=QHBoxLayout(); self.risk=QComboBox(); self.status=QComboBox()
        for level,_ in LEVELS:self.risk.addItem(level.capitalize(),level)
        for value,label in STATUSES:self.status.addItem(label,value)
        selectors.addWidget(self.risk); selectors.addWidget(self.status); edit.addLayout(selectors)
        self.reason=QLineEdit(); self.reason.setPlaceholderText("Correction reason (required)"); self.reason.setMaxLength(500); edit.addWidget(self.reason)
        self.save=QPushButton("Save correction"); self.save.clicked.connect(self.save_review); edit.addWidget(self.save)
        reload=QPushButton("Reload current review"); reload.clicked.connect(self.reload_review); edit.addWidget(reload)
        self.result=QLabel("This finding only. Evidence stays intact; future alerts remain enabled."); self.result.setWordWrap(True); self.result.setTextFormat(Qt.TextFormat.PlainText); self.result.setObjectName("eyebrow"); edit.addWidget(self.result)
        detail.addWidget(self.editor); self.editor.hide()
        self.evidence=QLabel("An empty queue does not establish safety. Inspect source limitations under Checks."); self.evidence.setTextFormat(Qt.TextFormat.RichText); self.evidence.setWordWrap(True); self.evidence.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse); detail.addWidget(self.evidence)
        self.inspect=QPushButton("Full evidence and timeline ↗"); self.inspect.clicked.connect(self.open_evidence); detail.addWidget(self.inspect); self.inspect.hide()
        self.history_text=QLabel(); self.history_text.setWordWrap(True); self.history_text.setTextFormat(Qt.TextFormat.PlainText); self.history_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse); detail.addWidget(self.history_text); detail.addStretch()
        split.setSizes([280,590]); self.engine.changed.connect(self.refresh); self.engine.config_done.connect(self.review_finished); self.engine.detail_ready.connect(self.review_loaded)
    def assessments(self):return {x["findingID"]:x for x in self.engine.snapshot.get("assessments",[])}
    def filter_level(self,level):
        self.level=level
        if level is not None:self.scope.setCurrentText("Open")
        self.refresh()
    def refresh(self,*_):
        snapshot=self.engine.snapshot; valid=bool(snapshot) and not self.engine.error
        counts=snapshot.get("riskCounts",{})
        self.total.setText(f"{sum(counts.values()) if valid and counts else '—'} OPEN FINDINGS")
        for level,color in LEVELS:
            text=f"{counts[level]:02d}" if valid and level in counts else "--"
            self.counters[level].setDigitCount(max(2,len(text))); self.counters[level].display(text); self.counters[level].setAccessibleName(f"{level}: {text} open findings")
        self.filter_label.setText((self.level or "ALL LEVELS").upper())
        if self.dashboard.page != "Overview": return
        reviewed=self.scope.currentText()=="Reviewed"; assessments=self.assessments(); query=self.search.text().casefold()
        rows=[f for f in snapshot.get("findings",[]) if f["id"] in assessments and ((assessments[f["id"]]["status"]!="open")==reviewed) and (self.level is None or assessments[f["id"]]["level"]==self.level) and (not query or query in (f["title"]+f["component"]+f["whyFlagged"]).casefold())]
        self.clear_queue.setVisible(not reviewed); self.clear_queue.setEnabled(valid and bool(rows) and not self.clearing)
        self.clear_queue.setText("Clearing…" if self.clearing else f"Clear queue ({len(rows)})…")
        order={level:i for i,(level,_) in enumerate(LEVELS)}; rows.sort(key=lambda f:(order[assessments[f["id"]]["level"]],-f["timestamp"]))
        self.queue_note.setText(("Queue limited to newest 1,000 records; risk counts include all findings. " if snapshot.get("findingsTruncated") else "")+("Store unavailable; retained records shown, counts unknown." if not valid else "Corrections never suppress future alerts."))
        new_signature=[(r["id"],assessments[r["id"]]) for r in rows]
        if getattr(self,"signature",None)==new_signature:return
        self.signature=new_signature; self.rows=rows; self.queue.blockSignals(True); self.queue.clear()
        for row in rows:
            a=assessments[row["id"]]; self.queue.addItem(f"{a['level'].upper()} · {a['status'].upper()}\n{row['title']}\n{row['component']}")
            self.queue.item(self.queue.count()-1).setForeground(QColor(dict(LEVELS)[a["level"]]))
        index=next((i for i,r in enumerate(rows) if r["id"]==self.selected),0 if rows else -1)
        self.queue.setCurrentRow(index); self.queue.blockSignals(False); self.select(index)
    def select(self,index):
        if not 0<=index<len(self.rows):
            self.selected=None; self.editor.hide(); self.inspect.hide(); self.heading.setText("No findings in this queue"); self.badge.clear(); self.history_text.clear(); self.evidence.setText("Choose another risk level or queue. No findings does not establish safety."); return
        row=self.rows[index]; a=self.assessments()[row["id"]]
        if self.selected==row["id"] and self.saved_assessment==a: return
        if self.selected==row["id"] and self.reason.text():
            self.result.setText("A newer correction exists. Your draft is retained; reload current review before saving."); return
        self.selected=row["id"]; self.saved_assessment=a
        self.revision=(a.get("latestReview") or {}).get("id"); self.heading.setText(row["title"])
        self.badge.setText(a["level"].upper()+" · "+a["status"].upper()+"\n"+row["component"]); self.badge.setStyleSheet("color:"+dict(LEVELS)[a["level"]])
        self.original.setText("Original suggestion: "+a["suggestedLevel"].capitalize()+". Observation confidence: "+row["confidence"]+". Intent remains unknown.")
        self.risk.setCurrentIndex(self.risk.findData(a["level"])); self.status.setCurrentIndex(self.status.findData(a["status"])); self.reason.clear(); self.editor.show(); self.inspect.show()
        sections=[("WHAT WAS FOUND",row["whatHappened"]),("WHY FLAGGED",row["whyFlagged"]),("SOURCE LIMITATIONS","\n".join(row.get("limitations",[]))),("SUGGESTED CHECKS","\n".join(row.get("suggestedInvestigation",[])))]
        self.evidence.setText("".join("<p style='color:#0de8ff'><b>"+escape(title)+"</b></p><p>"+escape(text).replace("\n","<br>")+"</p>" for title,text in sections))
        self.history_text.setText("Loading correction history…")
        self.engine.load_detail("review:"+self.selected,["review",self.selected,"--json"])
    def reload_review(self):
        self.reason.clear(); self.saved_assessment=None; self.select(self.queue.currentRow())
    def save_review(self):
        if not self.selected:return
        if not self.reason.text().strip():self.result.setText("Enter a reason for the correction.");return
        if self.engine.config.state().name != "NotRunning": self.result.setText("Another configuration change is saving. Try again when it completes."); return
        self.save.setEnabled(False)
        self.engine.configure_rule([self.selected,"--level",self.risk.currentData(),"--status",self.status.currentData(),"--reason",self.reason.text(),"--expected-review",self.revision or "none"],command="review")
    def confirm_clear_queue(self):
        if self.clearing or self.engine.error or self.scope.currentText()!="Open" or not self.rows:return
        assessments=self.assessments()
        targets=[{"findingID":row["id"],"expectedReviewID":(assessments[row["id"]].get("latestReview") or {}).get("id")} for row in self.rows]
        message=(f"Move these {len(targets)} displayed open findings to Reviewed with status Cleared? "
                 "Only findings matching the current level and search are included. "
                 "Evidence and risk levels stay intact. New findings stay open and future alerts remain enabled. "
                 "You can reopen cleared findings from Reviewed.")
        answer=QMessageBox.question(self,"Clear queue?",message,QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.Cancel,QMessageBox.StandardButton.Cancel)
        if answer!=QMessageBox.StandardButton.Yes:return
        if self.engine.config.state().name!="NotRunning":
            self.clear_result.setText("Another change is saving. Try again when it completes."); return
        self.clearing=True; self.clear_result.clear(); self.refresh()
        self.engine.configure_rule(["--clear-queue"],command="review",input_data=json.dumps(targets).encode("utf-8"))
    def review_finished(self,success,message):
        if self.engine.config_kind!="review":return
        if self.clearing:
            self.clearing=False; self.clear_result.setText(message); self.refresh(); return
        self.save.setEnabled(True); self.result.setText("Correction saved. Evidence retained; future alerts remain enabled." if success else message)
    def review_loaded(self,key,text):
        if key!="review:"+str(self.selected):return
        try:
            data=json.loads(text); history=data["history"]
        except (ValueError,KeyError,TypeError):self.history_text.setText("Review history unavailable. Refresh to retry.");return
        if data.get("accessContext"):
            self.evidence.setText(self.evidence.text()+"<p style='color:#0de8ff'><b>HOW WAS IT ACCESSED?</b></p><p>"+escape("\n\n".join(data["accessContext"])).replace("\n","<br>")+"</p>")
        self.history_text.setText("REVIEW HISTORY\n"+("\n\n".join(f"{datetime.fromtimestamp(r['timestamp']/1000,timezone.utc).isoformat()} · {r['previousLevel']} → {r['level']} · {r['previousStatus']} → {r['status']}\n{r['reason']}" for r in history) or "No corrections. Original classification retained."))
    def open_evidence(self):
        if not self.selected:return
        self.dashboard.open_page("Findings")
        self.dashboard.list.setCurrentRow(next((i for i,r in enumerate(self.dashboard.rows) if r["id"]==self.selected),-1))
