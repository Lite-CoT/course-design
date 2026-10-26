"""Development-only smoke test: real Qt widget rendering and worker signal path."""
import json
import traceback
from pathlib import Path
from PySide6.QtTest import QTest
from PySide6.QtCore import Qt
from election_service import create_election
from app_ui import trustee_process
from tally_service import aggregate
from common import write_json


def run_smoke(app,window,out):
    out.mkdir(parents=True,exist_ok=True)
    try:
        password='UiTest-2026!'
        e=create_election(out/'示例投票','班级活动方案投票',['科技馆参观','校园定向赛','读书分享会'],12,password)
        window.load_election(e)
        app.processEvents(); window.grab().save(str(out/'01_setup.png'))
        for i,choice in enumerate([0,1,0,2,0,1],1):
            window.voter_input.setText(f'V{i:04d}'); window.choice_input.setCurrentIndex(choice)
            QTest.mouseClick(window.cast_button,Qt.MouseButton.LeftButton)
            for _ in range(500):
                QTest.qWait(10)
                if window.stack.isEnabled():break
            assert len(e.payload['entries'])==i
        window.navigate(1); app.processEvents(); window.grab().save(str(out/'02_voting.png'))
        e.close(); window.refresh_view(); result=trustee_process(e.root,password,aggregate(e.root)); assert result['counts']==[3,2,1]
        window.display_result(result); app.processEvents(); window.grab().save(str(out/'03_results.png'))
        window.navigate(3); window.tamper_demo('change')
        for _ in range(500):
            QTest.qWait(10)
            if window.stack.isEnabled():break
        assert '篡改' in window.audit_log.toPlainText()
        window.tamper_demo('delete')
        for _ in range(500):
            QTest.qWait(10)
            if window.stack.isEnabled():break
        assert '删除' in window.audit_log.toPlainText()
        app.processEvents(); window.grab().save(str(out/'04_audit.png'))
        write_json(out/'ui_smoke.json',{'passed':True,'ui_votes':6,'counts':result['counts'],'subprocess_trustee':True,'tamper_demo':True,'delete_demo':True})
        window.close(); app.exit(0)
    except Exception:
        write_json(out/'ui_smoke.json',{'passed':False,'traceback':traceback.format_exc()}); app.exit(1)
