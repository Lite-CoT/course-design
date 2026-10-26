"""Member C: Qt desktop UI. Cryptographic work runs outside the UI thread."""
import csv
import json
import subprocess
import sys
import tempfile
import shutil
from pathlib import Path
from time import perf_counter
from PySide6.QtCore import Qt, QThread, Signal, QLockFile
from PySide6.QtGui import QColor, QPainter, QFont
from PySide6.QtWidgets import (QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QLabel,
    QPushButton, QStackedWidget, QLineEdit, QPlainTextEdit, QSpinBox, QComboBox,
    QFrame, QFormLayout, QFileDialog, QMessageBox, QInputDialog, QTableWidget,
    QTableWidgetItem, QHeaderView, QProgressBar)
from common import VoteError, read_json, write_json, digest
from election_service import create_election, Election
from audit_service import audit
from tally_service import aggregate

STYLE = '''
QMainWindow, QWidget { background:#f3f5f7; color:#183044; font-family:'Microsoft YaHei UI'; font-size:14px; }
QFrame#sidebar, QFrame#sidebar QLabel { background:#132d3c; color:#e7f2f4; }
QFrame#card, QFrame#card QLabel { background:white; }
QFrame#card { border:1px solid #dce5ea; border-radius:12px; }
QLabel#title { font-size:27px; font-weight:700; }
QLabel#subtitle { color:#637b8a; font-size:13px; }
QLabel#metric { font-size:28px; color:#087c79; font-weight:700; }
QPushButton { background:#087c79; color:white; border:none; border-radius:7px; padding:10px 18px; font-weight:600; }
QPushButton:hover { background:#096762; }
QPushButton:disabled { background:#c4ced4; color:#6b7b86; }
QPushButton#secondary { background:#e7eff3; color:#183d50; }
QPushButton#danger { background:#a4523e; }
QPushButton#nav { text-align:left; background:transparent; padding:14px 18px; color:#bdced8; }
QPushButton#nav:checked { background:#244858; color:white; border-left:4px solid #44c4b2; }
QLineEdit,QPlainTextEdit,QSpinBox,QComboBox { background:white; border:1px solid #cbd8df; border-radius:6px; padding:8px; min-height:22px; }
QTableWidget { background:white; border:1px solid #dce5ea; gridline-color:#edf1f4; border-radius:8px; }
QHeaderView::section { background:#e8eff3; padding:10px; border:0; color:#405d6d; }
QProgressBar { border:0; background:#e2eaef; height:6px; border-radius:3px; }
QProgressBar::chunk { background:#0a8b82; }
'''


class Job(QThread):
    done = Signal(object)
    failed = Signal(str)
    def __init__(self, fn):
        super().__init__(); self.fn=fn
    def run(self):
        try: self.done.emit(self.fn())
        except Exception as exc: self.failed.emit(str(exc))


class Bars(QWidget):
    def __init__(self):
        super().__init__(); self.labels=[]; self.values=[]; self.setMinimumHeight(220)
    def set_data(self, labels, values):
        self.labels=labels; self.values=values; self.update()
    def paintEvent(self,event):
        p=QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(),QColor('white'))
        if not self.values:
            p.setPen(QColor('#7a8f9e')); p.drawText(self.rect(),Qt.AlignmentFlag.AlignCenter,'投票关闭后，解密完整汇总以显示结果')
            return
        step=max(30,min(45,(self.height()-20)//len(self.values)))
        maxv=max(max(self.values),1)
        for i,(name,value) in enumerate(zip(self.labels,self.values)):
            y=10+i*step
            p.setPen(QColor('#254558')); p.drawText(8,y+20,name[:12])
            width=int((self.width()-210)*value/maxv)
            p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(['#08877d','#5b86ab','#a78a5a','#8089b4'][i%4]))
            p.drawRoundedRect(155,y,max(width,2),25,5,5)
            p.setPen(QColor('#254558')); p.drawText(165+width,y+19,str(value)+' 票')


def trustee_process(root,password,request):
    command=([sys.executable] if getattr(sys,'frozen',False) else [sys.executable,str(Path(__file__).with_name('main.py'))])+['--trustee']
    result=subprocess.run(command,input=json.dumps({'root':str(root),'password':password,'aggregate':request},ensure_ascii=True),
        text=True,capture_output=True,timeout=120,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    if result.returncode!=0:
        raise VoteError('解密进程运行失败：'+result.stderr[-300:])
    response=json.loads(result.stdout)
    if not response['ok']: raise VoteError(response['error'])
    return response['result']


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('密票实验室 · Paillier隐私投票'); self.resize(1180,820); self.setMinimumSize(1000,720)
        self.setStyleSheet(STYLE)
        self.election=None; self.result=None; self.job=None; self.lock=None; self.buttons=[]
        shell=QWidget(); self.setCentralWidget(shell); outer=QHBoxLayout(shell); outer.setContentsMargins(0,0,0,0); outer.setSpacing(0)
        sidebar=QFrame(); sidebar.setObjectName('sidebar'); sidebar.setFixedWidth(220); nav=QVBoxLayout(sidebar); nav.setContentsMargins(18,30,18,24)
        brand=QLabel('密票实验室'); brand.setStyleSheet('font-size:25px;font-weight:700;'); nav.addWidget(brand)
        tag=QLabel('PAILLIER  /  VOTING LAB'); tag.setStyleSheet('font-size:10px;color:#8cafbd;'); nav.addWidget(tag); nav.addSpacing(35)
        self.stack=QStackedWidget()
        for i,label in enumerate(['01   创建与管理','02   加密投票','03   汇总与结果','04   审计与实验']):
            btn=QPushButton(label); btn.setObjectName('nav'); btn.setCheckable(True); btn.clicked.connect(lambda _,i=i:self.navigate(i)); nav.addWidget(btn); self.buttons.append(btn)
        nav.addStretch(); note=QLabel('课程设计 · 题目 1\n\n成员 A  加密与密钥\n成员 B  汇总与解密\n成员 C  界面与审计'); note.setStyleSheet('color:#a9c2cd;font-size:12px;'); nav.addWidget(note)
        outer.addWidget(sidebar)
        main=QVBoxLayout(); main.setContentsMargins(28,24,28,18); outer.addLayout(main,1)
        self.heading=QLabel('创建与管理'); self.heading.setObjectName('title'); main.addWidget(self.heading)
        self.subtitle=QLabel('只展示总票数，让计票端只接触加密选票。'); self.subtitle.setObjectName('subtitle'); main.addWidget(self.subtitle)
        main.addSpacing(12)
        strip=QHBoxLayout(); self.metrics=[]
        for label in ['当前状态','已接收 / 授权人数','密钥长度']:
            card=QFrame(); card.setObjectName('card'); v=QVBoxLayout(card); v.addWidget(QLabel(label)); val=QLabel('—'); val.setObjectName('metric'); v.addWidget(val); strip.addWidget(card); self.metrics.append(val)
        main.addLayout(strip); main.addSpacing(12); main.addWidget(self.stack,1)
        self.progress=QProgressBar(); self.progress.setRange(0,0); self.progress.hide(); main.addWidget(self.progress)
        self.status=QLabel('就绪 · 数据保存在你选择的本地目录'); self.status.setWordWrap(True); self.status.setObjectName('subtitle'); main.addWidget(self.status)
        self.build_setup(); self.build_vote(); self.build_result(); self.build_audit(); self.navigate(0)

    def card(self, title):
        frame=QFrame(); frame.setObjectName('card'); layout=QVBoxLayout(frame); layout.setContentsMargins(20,18,20,18)
        heading=QLabel(title); heading.setStyleSheet('font-size:17px;font-weight:700;'); layout.addWidget(heading)
        return frame,layout

    def button(self,layout,text,callback,secondary=False):
        b=QPushButton(text); b.clicked.connect(callback)
        if secondary: b.setObjectName('secondary')
        layout.addWidget(b); return b

    def build_setup(self):
        page=QWidget(); v=QVBoxLayout(page); v.setContentsMargins(0,0,0,0)
        card,cv=self.card('新建一轮投票'); form=QFormLayout()
        self.title_input=QLineEdit('班级活动方案投票'); self.title_input.setMaxLength(80)
        self.options_input=QLineEdit('同意,反对,弃权')
        self.count_input=QSpinBox(); self.count_input.setRange(1,10000); self.count_input.setValue(30)
        self.password_input=QLineEdit(); self.password_input.setEchoMode(QLineEdit.EchoMode.Password); self.password_input.setPlaceholderText('至少8个字符，用于保护私钥；请自行保管')
        form.addRow('投票标题',self.title_input); form.addRow('选项（逗号分隔）',self.options_input); form.addRow('授权人数',self.count_input); form.addRow('私钥保管口令',self.password_input)
        cv.addLayout(form); info=QLabel('使用2048位Paillier；支持2至8个选项。授权ID自动生成：V0001、V0002……'); info.setWordWrap(True); cv.addWidget(info)
        row=QHBoxLayout(); self.button(row,'选择目录并创建',self.create_clicked); self.button(row,'打开已有投票',self.open_clicked,True); cv.addLayout(row); v.addWidget(card)
        card,cv=self.card('三个角色，一条可检查的计票流程')
        text=QLabel('投票端：选择 → 独热编码 → 随机加密\n计票端：校验ID → 接收密文 → 关闭投票 → 同态汇总\n解密端：核对完整清单 → 独立进程解密汇总 → 显示总票数')
        text.setStyleSheet('line-height:1.8;color:#4f6877;'); cv.addWidget(text)
        self.path_label=QLabel('尚未加载投票'); self.path_label.setWordWrap(True); cv.addWidget(self.path_label); v.addWidget(card); v.addStretch()
        self.stack.addWidget(page)

    def build_vote(self):
        page=QWidget(); v=QVBoxLayout(page); v.setContentsMargins(0,0,0,0)
        card,cv=self.card('提交一张加密选票'); form=QFormLayout()
        self.voter_input=QLineEdit('V0001'); self.voter_input.setPlaceholderText('授权名单中的ID，例如V0001')
        self.choice_input=QComboBox(); form.addRow('投票者ID',self.voter_input); form.addRow('选择一个选项',self.choice_input); cv.addLayout(form)
        row=QHBoxLayout(); self.cast_button=self.button(row,'加密并提交',self.cast_clicked); self.button(row,'解锁登记端',self.unlock_clicked,True); cv.addLayout(row)
        note=QLabel('提交后清空本地选择。下方只显示ID、时间与密文摘要，不显示投票内容。\nID名单校验不等于真实身份认证；本应用用于课程实验。'); note.setWordWrap(True); note.setObjectName('subtitle'); cv.addWidget(note); v.addWidget(card)
        self.table=QTableWidget(0,3); self.table.setHorizontalHeaderLabels(['投票者ID','接收时间 UTC','选票SHA-256摘要'])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch); self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows); self.table.cellDoubleClicked.connect(self.show_ciphertext); v.addWidget(self.table,1)
        row=QHBoxLayout(); self.button(row,'查看选中选票的密文',self.show_ciphertext,True); self.button(row,'关闭本轮投票',self.close_clicked); v.addLayout(row)
        self.stack.addWidget(page)

    def build_result(self):
        page=QWidget(); v=QVBoxLayout(page); v.setContentsMargins(0,0,0,0)
        card,cv=self.card('先汇总，再解密'); self.result_note=QLabel('尚未生成结果。必须先关闭投票；开放期间不允许查询阶段票数。'); self.result_note.setWordWrap(True); cv.addWidget(self.result_note)
        row=QHBoxLayout(); self.button(row,'审计并解密总票数',self.tally_clicked); self.button(row,'导出结果 CSV',self.export_csv,True); self.button(row,'导出无私钥公开包',self.export_public,True); cv.addLayout(row)
        self.chart=Bars(); cv.addWidget(self.chart,1); v.addWidget(card,1)
        self.timing=QLabel('汇总与解密耗时将在成功计票后显示'); self.timing.setWordWrap(True); v.addWidget(self.timing)
        info=QLabel('隐私边界：单机角色分离用于演示；持有完整私钥的人仍可解密单票。\n如果只有一人投票，总结果本身会暴露其选择。真实部署需要独立保管和最小参与人数策略。'); info.setWordWrap(True); info.setObjectName('subtitle'); v.addWidget(info)
        self.stack.addWidget(page)

    def build_audit(self):
        page=QWidget(); v=QVBoxLayout(page); v.setContentsMargins(0,0,0,0)
        card,cv=self.card('额外功能 · 关闭投票与签名清单审计')
        note=QLabel('每张已接收选票的摘要登记在Ed25519签名清单中。\n演示操作只修改临时副本，不改变当前投票数据。'); note.setWordWrap(True); cv.addWidget(note)
        row=QHBoxLayout(); self.button(row,'检查当前投票',self.audit_clicked); self.button(row,'演示篡改检测',lambda:self.tamper_demo('change'),True); self.button(row,'演示删除检测',lambda:self.tamper_demo('delete'),True); cv.addLayout(row)
        row=QHBoxLayout(); self.button(row,'自动实验与性能测试',self.experiments_clicked,True); cv.addLayout(row); v.addWidget(card)
        self.audit_log=QPlainTextEdit(); self.audit_log.setReadOnly(True); self.audit_log.setPlaceholderText('审计结果与实验记录显示在这里'); v.addWidget(self.audit_log,1)
        warning=QLabel('安全局限：不提供加密选票合法性的零知识证明；整套旧签名数据回滚无法仅靠本地清单识别。'); warning.setWordWrap(True); warning.setObjectName('subtitle'); v.addWidget(warning); self.stack.addWidget(page)

    def navigate(self,index):
        self.stack.setCurrentIndex(index)
        self.heading.setText(['创建与管理','加密投票','汇总与结果','审计与实验'][index])
        for i,b in enumerate(self.buttons): b.setChecked(i==index)

    def run_job(self,fn,callback,message):
        if self.job is not None and self.job.isRunning(): return
        self.stack.setEnabled(False); self.progress.show(); self.status.setText(message)
        self.job=Job(fn); self.job.done.connect(lambda value:self.job_success(value,callback)); self.job.failed.connect(self.job_error)
        self.job.start()

    def job_success(self,value,callback):
        # done is emitted just before run() exits; wait before allowing the next job.
        self.job.wait()
        self.stack.setEnabled(True); self.progress.hide()
        try: callback(value)
        except Exception as exc: self.job_error(str(exc))

    def job_error(self,error):
        if self.job and self.job.isRunning(): self.job.wait()
        self.stack.setEnabled(True); self.progress.hide(); self.status.setText('操作未完成：'+error)
        QMessageBox.warning(self,'操作未完成',error)

    def require_election(self):
        if not self.election: raise VoteError('请先创建或打开一轮投票')
        return self.election

    def load_election(self,election):
        if not self.election or self.election.root.resolve()!=election.root.resolve():
            lock=QLockFile(str(election.root/'app.lock')); lock.setStaleLockTime(0)
            if not lock.tryLock(0): raise VoteError('该投票正在另一个应用窗口中使用')
            if self.lock: self.lock.unlock()
            self.lock=lock
        self.election=election; self.result=None; self.chart.set_data([],[])
        self.result_note.setText('本轮结果尚未在当前会话解密。'); self.timing.setText('请先关闭投票，再计票。')
        self.refresh_view(); self.status.setText('投票已加载 · '+election.config['title'])

    def refresh_view(self):
        e=self.require_election(); ballots=e.refresh()
        self.metrics[0].setText('已关闭' if e.payload['status']=='closed' else '投票中')
        self.metrics[1].setText(f"{len(ballots)} / {len(e.config['roster'])}")
        self.metrics[2].setText(str(e.config['key_bits'])+' bit')
        self.path_label.setText('本地目录：'+str(e.root)+'\n配置指纹：'+digest(e.config)[:24])
        self.choice_input.clear(); self.choice_input.addItems(e.config['options']); self.choice_input.setCurrentIndex(-1)
        self.table.setRowCount(len(ballots))
        for i,(b,entry) in enumerate(zip(ballots,e.payload['entries'])):
            for j,value in enumerate([b['voter_id'],b['timestamp'],entry['sha256'][:24]+'…']):
                self.table.setItem(i,j,QTableWidgetItem(value))
        self.cast_button.setEnabled(e.payload['status']=='open')

    def create_clicked(self):
        password=self.password_input.text()
        if len(password)<8: self.job_error('保管口令至少需要8个字符'); return
        parent=QFileDialog.getExistingDirectory(self,'选择保存位置（会自动创建新的投票子目录）')
        if not parent: return
        import uuid
        root=Path(parent)/('投票_'+uuid.uuid4().hex[:8]); title=self.title_input.text(); count=self.count_input.value()
        options=self.options_input.text().replace('，',',').split(','); self.password_input.clear()
        self.run_job(lambda:create_election(root,title,options,count,password),self.load_election,'正在生成2048位密钥和新投票……')

    def open_clicked(self):
        root=QFileDialog.getExistingDirectory(self,'选择包含public目录的投票文件夹')
        if root: self.run_job(lambda:Election(root),self.load_election,'正在验证签名清单……')

    def unlock_clicked(self):
        try: e=self.require_election()
        except Exception as exc: self.job_error(str(exc)); return
        password,ok=QInputDialog.getText(self,'解锁登记端','输入私钥保管口令',QLineEdit.EchoMode.Password)
        if ok: self.run_job(lambda:e.unlock_registrar(password),lambda _:self.status.setText('登记端已解锁，可接收选票和关闭投票'),'正在解锁登记签名密钥……')

    def cast_clicked(self):
        try: e=self.require_election()
        except Exception as exc: self.job_error(str(exc)); return
        voter=self.voter_input.text().strip(); choice=self.choice_input.currentIndex()
        start=perf_counter()
        def done(receipt):
            self.refresh_view(); self.status.setText(f'已接收 {voter} · 耗时 {(perf_counter()-start)*1000:.1f} ms · 回执 {receipt[:16]}')
            used={x['voter_id'] for x in e.payload['entries']}; remaining=[x for x in e.config['roster'] if x not in used]
            if remaining: self.voter_input.setText(remaining[0])
        self.run_job(lambda:e.cast(voter,choice),done,'正在随机加密并登记选票……')

    def close_clicked(self):
        try: e=self.require_election()
        except Exception as exc: self.job_error(str(exc)); return
        if QMessageBox.question(self,'关闭投票','关闭后本轮不能继续投票。确认所有选票已经提交？') != QMessageBox.StandardButton.Yes: return
        self.run_job(e.close,lambda _:(self.refresh_view(),self.status.setText('投票已关闭，可以汇总解密')),'正在签署关闭状态……')

    def tally_clicked(self):
        try: e=self.require_election()
        except Exception as exc: self.job_error(str(exc)); return
        if e.payload['status']!='closed': self.job_error('请先在加密投票页面关闭投票'); return
        password,ok=QInputDialog.getText(self,'解密端授权','输入私钥保管口令，仅用于独立进程解密汇总',QLineEdit.EchoMode.Password)
        if ok: self.run_job(lambda:trustee_process(e.root,password,aggregate(e.root)),self.display_result,'正在审计、同态汇总并由独立进程解密……')

    def display_result(self,result):
        self.result=result; self.chart.set_data(result['options'],result['counts'])
        self.result_note.setText(f"{result['title']} · 有效票 {result['accepted']} / 授权人数 {result['eligible']} · 审计通过")
        self.timing.setText(f"审计 {result['audit_ms']:.2f} ms    密文汇总 {result['aggregate_ms']:.2f} ms    汇总解密 {result['decrypt_ms']:.2f} ms\n耗时不包含口令派生与进程启动；明细仅显示总票数。")
        self.status.setText('计票完成 · 总票数校验通过'); self.navigate(2)

    def show_ciphertext(self,*args):
        try:
            e=self.require_election(); row=self.table.currentRow()
            if row<0: raise VoteError('请先选择一张选票')
            path=e.root/'public/ballots'/e.payload['entries'][row]['file']
            box=QMessageBox(self); box.setWindowTitle('公开选票 · 不含明文选择'); box.setText('以下是该选票的公开字段。展开详细信息可查看完整密文。')
            box.setDetailedText(json.dumps(read_json(path),ensure_ascii=False,indent=2)); box.exec()
        except Exception as exc: self.job_error(str(exc))

    def export_csv(self):
        if not self.result: self.job_error('请先完成计票'); return
        path,_=QFileDialog.getSaveFileName(self,'导出结果','投票结果.csv','CSV (*.csv)')
        if not path:return
        try:
            with open(path,'w',encoding='utf-8-sig',newline='') as f:
                w=csv.writer(f); w.writerow(['选项','票数']); w.writerows(zip(self.result['options'],self.result['counts']))
            self.status.setText('已导出：'+path)
        except Exception as exc: self.job_error(str(exc))

    def export_public(self):
        try: e=self.require_election()
        except Exception as exc:self.job_error(str(exc));return
        path,_=QFileDialog.getSaveFileName(self,'导出无私钥公开包','公开计票包.zip','ZIP (*.zip)')
        if path:self.run_job(lambda:e.export_public(path),lambda p:self.status.setText('已导出：'+p),'正在导出公开数据……')

    def audit_clicked(self):
        try:e=self.require_election()
        except Exception as exc:self.job_error(str(exc));return
        def done(value):
            _,m,b=value; self.audit_log.appendPlainText(f"审计通过：{len(b)} 张已登记选票；状态 {m['status']}；签名、摘要、ID、文件集合一致。")
            self.status.setText('当前投票审计通过')
        self.run_job(lambda:audit(e.root),done,'正在核对签名清单与全部选票……')

    def tamper_demo(self,kind):
        try:
            e=self.require_election()
            if not e.payload['entries']:raise VoteError('至少提交一张选票后才能演示')
        except Exception as exc:self.job_error(str(exc));return
        def run():
            with tempfile.TemporaryDirectory(prefix='audit-demo-') as temp:
                target=Path(temp)/'copy'; shutil.copytree(e.root/'public',target/'public')
                p=next((target/'public/ballots').glob('*.json'))
                if kind=='delete':p.unlink()
                else:
                    b=read_json(p); b['ciphertexts'][0]='1'; write_json(p,b)
                try:audit(target)
                except Exception as exc:return '临时副本实验：'+str(exc)+'\n当前投票原始数据保持完整。'
                raise VoteError('审计未检测出修改')
        self.run_job(run,lambda msg:(self.audit_log.appendPlainText(msg),self.status.setText('审计演示完成')),'正在临时副本上执行审计实验……')

    def experiments_clicked(self):
        path=QFileDialog.getExistingDirectory(self,'选择实验结果保存位置')
        if not path:return
        from experiments import run_experiments
        import uuid
        output=Path(path)/('实验_'+uuid.uuid4().hex[:8])
        def done(report):
            self.audit_log.appendPlainText(f"实验完成：{report['passed']} / {report['total']} 项通过。\n报告与CSV：{output}")
            self.status.setText('实验完成 · 包含实际性能数据和安全局限验证')
        self.run_job(lambda:run_experiments(output),done,'自动实验进行中：2048位密钥，10/100/1000人各3次，预计约1至2分钟……')

    def closeEvent(self,event):
        if self.job and self.job.isRunning():
            event.ignore(); self.status.setText('请等待当前任务完成后关闭应用'); return
        if self.lock:self.lock.unlock()
        super().closeEvent(event)
