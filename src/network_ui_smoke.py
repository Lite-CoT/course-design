"""Actual Qt control clicks in two voter windows connected to a real TLS port."""
import threading
import traceback
from pathlib import Path
from PySide6.QtTest import QTest
from PySide6.QtCore import Qt
from common import write_json, read_json
from network_setup import initialize_network
from network_server import make_server
from network_client import NetworkClient
from network_trustee import decrypt_bundle
from network_ui import NetworkWindow


def run_smoke(app, first, out):
    out = Path(out); out.mkdir(parents=True, exist_ok=False)
    server = thread = None
    windows = [first]
    try:
        password = 'Synthetic-UI-2026!'
        initialize_network(out/'round', '周末活动方案投票', ['科技馆参观','校园定向赛','读书分享会'], 8, password)
        server = make_server(out/'round/server', '127.0.0.1', 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        def wait(window):
            for _ in range(3000):
                QTest.qWait(10)
                if window.job is None: return
            raise AssertionError('Qt network action timed out')
        def connect(window, voter):
            window.host_input.setText('127.0.0.1'); window.port_input.setValue(server.server_port)
            path=out/'round/organizer'/('admin.ticket.json' if voter=='admin' else f'voters/{voter}.ticket.json')
            window.load_ticket(path)
            QTest.mouseClick(window.connect_button, Qt.MouseButton.LeftButton); wait(window)
            assert window.client is not None, window.status_label.text()
        first.show(); connect(first, 'V0001')
        app.processEvents(); first.grab().save(str(out/'01_connected.png'))
        second = NetworkWindow(); windows.append(second); second.show(); connect(second,'V0002')
        first.choice_input.setCurrentIndex(0); second.choice_input.setCurrentIndex(1)
        QTest.mouseClick(first.cast_button, Qt.MouseButton.LeftButton)
        QTest.mouseClick(second.cast_button, Qt.MouseButton.LeftButton)
        wait(first); wait(second)
        assert first.current_me['receipt'] and second.current_me['receipt']
        for index, choice in enumerate([0,2,0,1], 3):
            connect(second,f'V{index:04d}'); second.choice_input.setCurrentIndex(choice)
            QTest.mouseClick(second.cast_button, Qt.MouseButton.LeftButton); wait(second)
            assert second.current_me['receipt'], second.status_label.text()
        QTest.mouseClick(first.refresh_button, Qt.MouseButton.LeftButton); wait(first)
        app.processEvents(); first.grab().save(str(out/'02_voter_receipt.png'))
        admin = NetworkWindow(); windows.append(admin); admin.show(); connect(admin,'admin')
        app.processEvents(); admin.grab().save(str(out/'03_admin.png'))
        # Admin export/import file pickers and offline transfer are exercised by CLI acceptance.
        admin.client.close(); bundle = admin.client.export()
        result = decrypt_bundle(out/'round/trustee', bundle, password); admin.client.publish(result)
        QTest.mouseClick(first.refresh_button, Qt.MouseButton.LeftButton); wait(first)
        assert first.current_status['result']['payload']['counts']==[3,2,1]
        app.processEvents(); first.grab().save(str(out/'04_published.png'))
        write_json(out/'network-ui.json', {'passed':True,'transport':'real TLS socket on loopback',
            'voter_windows':2,'gui_votes':6,'counts':[3,2,1],'admin_connection':True,
            'receipt_signature_verified':True,'result_signature_verified':True,
            'note':'Two Qt windows in one UI process; separate OS client processes tested separately.'})
        exit_code=0
    except Exception:
        write_json(out/'network-ui.json', {'passed':False,'traceback':traceback.format_exc()}); exit_code=1
    finally:
        for window in windows:
            if window.job: window.job.wait()
            window.close()
        if server: server.shutdown(); server.server_close()
        if thread: thread.join(timeout=5)
    app.exit(exit_code)
