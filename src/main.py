"""Packaged desktop entry and isolated trustee subprocess protocol."""
import json
import sys
from pathlib import Path


def main():
    from network_cli import COMMANDS
    if len(sys.argv) > 1 and sys.argv[1] in COMMANDS:
        from network_cli import run
        sys.exit(run(sys.argv[1:]))
    if '--trustee' in sys.argv:
        from tally_service import decrypt_tally
        try:
            request = json.loads(sys.stdin.read())
            result = decrypt_tally(request['root'], request['password'], request['aggregate'])
            sys.stdout.write(json.dumps({'ok':True,'result':result},ensure_ascii=True))
        except Exception as exc:
            sys.stdout.write(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=True))
        return
    if '--experiments' in sys.argv:
        from experiments import run_experiments
        out = Path(sys.argv[sys.argv.index('--experiments')+1])
        r = run_experiments(out, full='--quick' not in sys.argv)
        if sys.stdout:
            print(json.dumps({'passed':r['passed'],'total':r['total']},ensure_ascii=True))
        sys.exit(0 if r['passed']==r['total'] else 1)
    from PySide6.QtWidgets import QApplication
    from PySide6.QtGui import QFont
    app = QApplication(sys.argv)
    app.setApplicationName('密票实验室')
    app.setFont(QFont('Microsoft YaHei UI',10))
    if '--local-demo' in sys.argv or '--ui-smoke' in sys.argv:
        from app_ui import MainWindow
        window = MainWindow()
    else:
        from network_ui import NetworkWindow
        window = NetworkWindow()
    window.show()
    if '--ui-smoke' in sys.argv:
        from PySide6.QtCore import QTimer
        from ui_smoke import run_smoke
        out = Path(sys.argv[sys.argv.index('--ui-smoke')+1])
        QTimer.singleShot(300, lambda: run_smoke(app,window,out))
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
