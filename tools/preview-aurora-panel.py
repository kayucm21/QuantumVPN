"""Local-only UI fixture; no VDS/network/service workers are started."""
import argparse
import os
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8771)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='aurora-ui-') as fixture:
        os.environ.update(QV_DATA_DIR=fixture, QV_DOWNLOAD_ROOT=fixture,
                          QV_ADMIN_USER='preview', QV_ADMIN_PASSWORD='preview-local',
                          QV_SUBSCRIPTION_UPSTREAM='https://example.invalid/sub',
                          QV_ROSPANEL_DB=fixture+'/absent.db')
        import quantumvpn_operator_panel as panel
        now = int(time.time())
        panel.cached_rospanel_summary = lambda *a, **kw: {'ok': True, 'active': 6, 'disabled': 1, 'expired': 0, 'online_15m': 3, 'traffic_today_gb': 2.4}
        panel.cached_service_status = lambda *a, **kw: {'rospanel': 'active', 'operator': 'active', 'xray': 'active', 'opera': 'active', 'cpu_load_pct': 6, 'memory_used_pct': 35, 'disk_used_pct': 41, 'disk_free_gb': 34, 'outbounds': []}
        panel.rospanel_users = lambda *a, **kw: [(f'demo_user_{101+i}', 1, 'active', 100_000_000, 200_000_000, now+86400*30, now-120*i, str(i)) for i in range(6)]
        with panel.conn() as db:
            panel.set_settings(db, {'node_map_config': 'Demo Paris|203.0.113.10:443|48.8534|2.3488|Paris · demo\nDemo Frankfurt|203.0.113.11:443|50.1109|8.6821|Frankfurt · demo', 'app_version': '5.11.1', 'app_version_code': '501101099'})
            for i in range(6):
                db.execute('insert into events values (?,?,?,?,?)', (now-i*60, 'UI-preview', 'demo_user_'+str(101+i), '', 'Тестовое событие локального предпросмотра'))
            db.commit()
        server = panel.OperatorHTTPServer(('127.0.0.1', args.port), panel.App)
        print(f'http://127.0.0.1:{args.port}/operator/login', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()


if __name__ == '__main__':
    main()
