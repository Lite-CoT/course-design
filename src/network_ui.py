"""Desktop voter/admin client. Connect by LAN IP and port; encrypt locally."""
from pathlib import Path
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QSpinBox, QPushButton, QGroupBox, QFormLayout, QComboBox, QPlainTextEdit,
    QFileDialog, QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView)
from common import read_json, write_json, VoteError
from network_client import NetworkClient, validate_ticket


class Work(QThread):
    succeeded = Signal(object)
    failed = Signal(str)
    def __init__(self, fn, parent):
        super().__init__(parent)
        self.fn = fn
    def run(self):
        try: self.succeeded.emit(self.fn())
        except Exception as exc: self.failed.emit(str(exc))


class NetworkWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.client = self.ticket = self.job = None
        self.current_status = self.current_me = None
        self.setWindowTitle('密票实验室 · 局域网投票客户端')
        self.resize(1140, 820)
        self.setMinimumSize(940, 720)
        self.setStyleSheet('''
            QWidget {font-family:"Microsoft YaHei UI";font-size:14px;color:#19354a;}
            QMainWindow {background:#f2f5f8;}
            QGroupBox {background:white;border:1px solid #dae3eb;border-radius:9px;margin-top:14px;padding:20px 14px 12px;}
            QGroupBox::title {subcontrol-origin:margin;left:15px;font-weight:bold;}
            QLineEdit,QSpinBox,QComboBox {padding:8px;border:1px solid #cad8e2;border-radius:5px;background:white;}
            QPushButton {background:#087c79;color:white;border:0;border-radius:6px;padding:11px 14px;font-weight:bold;}
            QPushButton:disabled {background:#b8c8d0;color:#f7fafc;}
            QPushButton#secondary {background:#e5eef3;color:#25485d;}
            QPlainTextEdit,QTableWidget {background:#fbfdff;border:1px solid #dce6ed;border-radius:5px;}
            QLabel#subtle {color:#5c7485;font-size:12px;}
        ''')
        self.content = QWidget(); self.setCentralWidget(self.content)
        outer = QVBoxLayout(self.content); outer.setContentsMargins(26, 20, 26, 20); outer.setSpacing(14)
        title = QLabel('密票  /  局域网同态投票'); title.setStyleSheet('font-size:27px;font-weight:bold;')
        outer.addWidget(title)
        subtitle = QLabel('客户端加密选票 → 服务器汇总密文 → 保管端解密总票')
        subtitle.setObjectName('subtle'); outer.addWidget(subtitle)
        columns = QHBoxLayout(); outer.addLayout(columns, 1)
        left = QVBoxLayout(); columns.addLayout(left, 2)
        right = QVBoxLayout(); columns.addLayout(right, 3)
        connection = QGroupBox('01  连接服务器'); form = QFormLayout(connection)
        self.host_input = QLineEdit('127.0.0.1')
        self.port_input = QSpinBox(); self.port_input.setRange(1, 65535); self.port_input.setValue(8443)
        form.addRow('服务器 IP', self.host_input); form.addRow('投票端口', self.port_input)
        self.ticket_label = QLabel('尚未导入凭证'); self.ticket_label.setWordWrap(True)
        self.import_button = QPushButton('导入投票 / 管理凭证'); self.import_button.setObjectName('secondary')
        self.import_button.clicked.connect(self.import_ticket)
        form.addRow(self.import_button); form.addRow(self.ticket_label)
        self.connect_button = QPushButton('连接服务器'); self.connect_button.clicked.connect(self.connect_clicked)
        form.addRow(self.connect_button); left.addWidget(connection)
        info = QLabel('同一局域网：填写服务器电脑的 IPv4 地址。\n本机多端测试：所有窗口填写 127.0.0.1，分别导入不同投票凭证。')
        info.setWordWrap(True); info.setObjectName('subtle'); left.addWidget(info)
        self.receipt_box = QGroupBox('已验证的接收回执'); rlayout = QVBoxLayout(self.receipt_box)
        self.receipt_text = QPlainTextEdit(); self.receipt_text.setReadOnly(True)
        self.receipt_text.setPlaceholderText('提交成功后显示回执。连接中断时先刷新，核对该 ID 是否已被接收。')
        rlayout.addWidget(self.receipt_text); left.addWidget(self.receipt_box, 1)
        election = QGroupBox('02  当前投票'); el = QVBoxLayout(election)
        self.election_title = QLabel('连接后获取投票题目'); self.election_title.setWordWrap(True)
        self.election_title.setStyleSheet('font-size:20px;font-weight:bold;'); el.addWidget(self.election_title)
        self.metrics = QLabel('未连接'); el.addWidget(self.metrics)
        self.choice_input = QComboBox(); self.choice_input.setMinimumHeight(40); el.addWidget(self.choice_input)
        self.cast_button = QPushButton('在本端加密并提交选票'); self.cast_button.clicked.connect(self.cast_clicked); el.addWidget(self.cast_button)
        self.refresh_button = QPushButton('刷新状态 / 我的回执'); self.refresh_button.setObjectName('secondary')
        self.refresh_button.clicked.connect(self.refresh_clicked); el.addWidget(self.refresh_button)
        right.addWidget(election)
        self.admin_box = QGroupBox('管理员操作'); admin = QHBoxLayout(self.admin_box)
        self.close_button = QPushButton('关闭投票'); self.close_button.clicked.connect(self.close_clicked)
        self.export_button = QPushButton('导出密文汇总'); self.export_button.clicked.connect(self.export_clicked)
        self.publish_button = QPushButton('发布签名结果'); self.publish_button.clicked.connect(self.publish_clicked)
        for button in (self.close_button, self.export_button, self.publish_button): admin.addWidget(button)
        right.addWidget(self.admin_box)
        results = QGroupBox('03  公开总票数'); rv = QVBoxLayout(results)
        self.result_note = QLabel('关闭投票并经保管端批准后，服务器公布签名总票。'); self.result_note.setWordWrap(True)
        rv.addWidget(self.result_note)
        self.result_table = QTableWidget(0, 2); self.result_table.setHorizontalHeaderLabels(['选项', '总票数'])
        self.result_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.result_table.verticalHeader().hide(); self.result_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        rv.addWidget(self.result_table); right.addWidget(results, 1)
        self.status_label = QLabel('就绪 · 先导入本人的凭证，再输入 IP 和端口连接')
        self.status_label.setWordWrap(True); outer.addWidget(self.status_label)
        self.apply_permissions()

    def load_ticket(self, path):
        ticket = read_json(path, 16000); validate_ticket(ticket)
        self.ticket, self.client = ticket, None
        self.current_status = self.current_me = None
        identity = ticket['voter_id'] if ticket['role']=='voter' else '管理员'
        self.ticket_label.setText(f'身份：{identity}\n凭证：{Path(path).name}')
        self.receipt_text.clear(); self.choice_input.clear(); self.result_table.setRowCount(0)
        self.election_title.setText('连接后获取投票题目'); self.metrics.setText('未连接')
        self.apply_permissions()

    def import_ticket(self):
        path, _ = QFileDialog.getOpenFileName(self, '选择本人凭证', '', '投票凭证 (*.json)')
        if path:
            try: self.load_ticket(path)
            except (VoteError, OSError) as exc: self.status_label.setText(str(exc))

    def work(self, fn, done, message):
        if self.job is not None: return
        self.content.setEnabled(False); self.status_label.setText(message)
        job = Work(fn, self); self.job = job
        def finish(value=None, error=None):
            job.wait(); self.job = None; job.deleteLater(); self.content.setEnabled(True)
            try:
                if error is not None: self.status_label.setText('操作失败：'+error)
                else: done(value)
            except Exception as exc: self.status_label.setText('处理响应失败：'+str(exc))
            self.apply_permissions()
        job.succeeded.connect(lambda value: finish(value))
        job.failed.connect(lambda error: finish(error=error))
        job.start()

    def connect_clicked(self):
        if self.ticket is None:
            self.status_label.setText('请先导入组织者发给本人的凭证'); return
        try: client = NetworkClient(self.host_input.text(), self.port_input.value(), self.ticket)
        except VoteError as exc: self.status_label.setText(str(exc)); return
        self.client = None; self.apply_permissions()
        def done(value):
            self.client = client
            self.election_title.setText(client.election['config']['title'])
            self.choice_input.clear(); self.choice_input.addItems(client.election['config']['options'])
            self.render(value['status'], value['me'])
            self.status_label.setText(f'已验证服务器证书与配置 · {client.host}:{client.port}')
        self.work(client.connect, done, '正在建立加密连接并验证凭证……')

    def render(self, status, me):
        self.current_status, self.current_me = status, me
        state = '投票中' if status['status']=='open' else '已关闭'
        self.metrics.setText(f'{state}    已接收 {status["accepted"]} / {status["eligible"]} 票')
        receipt = me.get('receipt')
        if receipt:
            data = receipt['payload']
            self.receipt_text.setPlainText(f'ID：{data["voter_id"]}\n接收时间：{data["accepted_at"]}\n\n选票摘要：\n{data["ballot_sha256"]}\n\n服务器签名：已验证')
        else: self.receipt_text.clear()
        self.result_table.setRowCount(0)
        if status['result']:
            result = status['result']['payload']
            self.result_note.setText(f'保管端签名已验证 · 有效票 {result["accepted"]} · 只公布各选项总票')
            for index, (label, count) in enumerate(zip(self.client.election['config']['options'], result['counts'])):
                self.result_table.insertRow(index)
                self.result_table.setItem(index, 0, QTableWidgetItem(label))
                self.result_table.setItem(index, 1, QTableWidgetItem(str(count)))
        else: self.result_note.setText('尚未发布总票。管理员关闭投票后交由保管端解密完整汇总。')

    def apply_permissions(self):
        connected = self.client is not None
        admin = connected and self.ticket['role']=='admin'
        opened = connected and self.current_status and self.current_status['status']=='open'
        voted = self.current_me and self.current_me.get('receipt') is not None
        self.cast_button.setEnabled(bool(connected and not admin and opened and not voted))
        self.choice_input.setEnabled(bool(connected and not admin and opened and not voted))
        self.refresh_button.setEnabled(connected)
        self.admin_box.setVisible(bool(admin))
        self.close_button.setEnabled(bool(admin and opened))
        self.export_button.setEnabled(bool(admin and not opened))
        self.publish_button.setEnabled(bool(admin and not opened))

    def refresh_clicked(self):
        if not self.client: return
        self.work(lambda: (self.client.status(), self.client.me()),
                  lambda data: (self.render(*data), self.status_label.setText('状态与回执已刷新')),
                  '正在刷新服务器状态……')

    def cast_clicked(self):
        if not self.client: return
        choice = self.choice_input.currentIndex()
        def cast():
            receipt = self.client.vote(choice)
            return receipt, self.client.status(), self.client.me()
        def done(data):
            self.render(data[1], data[2])
            self.status_label.setText(f'选票已接收 · 回执验证通过 · 本端加密 {self.client.last_vote_metrics["encrypt_ms"]:.2f} ms')
        self.work(cast, done, '在本端随机加密选票，正在提交密文……')

    def close_clicked(self):
        if QMessageBox.question(self, '关闭投票', '关闭后不能追加选票，确认所有人已提交？') != QMessageBox.StandardButton.Yes: return
        self.work(lambda: (self.client.close(), self.client.me()),
                  lambda data: (self.render(*data), self.status_label.setText('投票已关闭，可导出完整密文汇总')),
                  '正在关闭投票……')

    def export_clicked(self):
        path, _ = QFileDialog.getSaveFileName(self, '保存供保管端复核的密文汇总', '密文汇总.json', 'JSON (*.json)')
        if path:
            self.work(self.client.export, lambda bundle: (write_json(path, bundle), self.status_label.setText('已导出完整密文汇总；交给独立保管端')),
                      '服务器正在审计并汇总密文……')

    def publish_clicked(self):
        path, _ = QFileDialog.getOpenFileName(self, '选择保管端签署的总票结果', '', 'JSON (*.json)')
        if path:
            self.work(lambda: (self.client.publish(read_json(path, 128000)), self.client.me()),
                      lambda data: (self.render(*data), self.status_label.setText('签名结果已发布，各端可刷新查看')),
                      '正在核验并发布保管端签名结果……')

    def closeEvent(self, event):
        if self.job is not None:
            self.status_label.setText('请等待当前网络操作完成后关闭'); event.ignore()
        else: event.accept()
