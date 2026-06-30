"""
DJI Login Backend — chạy local, expose qua ngrok.

Endpoint:
  POST /dji/login   { username, password }
                    → { success, requiresOTP, cookies, json, ... }
  POST /dji/otp     { username, password, otpCode, cookies }
                    → { success, cookies, json }
  POST /dji/resend  { username, password }
                    → { success }
  GET  /health      → { service: 'ok' }

Cách chạy:
  pip install flask flask-cors requests
  python dji_backend.py            # http://localhost:5000
  ngrok http 5000                  # terminal khác

Sau đó copy URL ngrok vào Settings.ngrok_url trong GAS.
"""

import os
import sys
import json
import time
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DJI_BASE = 'https://dealersystem-abroad.dji.com'
UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'


def build_proxies():
    """Đọc proxy từ env. Hỗ trợ SOCKS5 và HTTP/S proxy.
    Env: PROXY_URL=socks5://user:pass@host:port hoặc http://user:pass@host:port
         PROXY_ENABLED=1 để bật.
    """
    if os.environ.get('PROXY_ENABLED', '1') not in ('1', 'true', 'True'):
        return {}
    url = os.environ.get('PROXY_URL', '').strip()
    if not url:
        return {}
    if url.startswith('socks5://'):
        proxy_url = 'socks5h://' + url[len('socks5://'):]
    else:
        proxy_url = url
    print(f'[PROXY] enabled: {proxy_url.split("@")[-1]}', flush=True)
    return {'http': proxy_url, 'https': proxy_url}


session = requests.Session()
session.headers.update({'User-Agent': UA})
session.proxies.update(build_proxies())


def get_session_cookies():
    """Bước 1+2: GET base + login page → cookies."""
    session.cookies.clear()
    try:
        r1 = session.get(DJI_BASE, timeout=15)
        r2 = session.get(f'{DJI_BASE}/en/Home/Login', timeout=15)
    except Exception as e:
        print(f'[WARN] session GET failed: {e}', file=sys.stderr)
    return '; '.join(f'{c.name}={c.value}' for c in session.cookies)


def cookies_to_string(jar):
    return '; '.join(f'{c.name}={c.value}' for c in jar)


def check_login(username, password):
    """POST /en/Home/CheckLogin."""
    url = f'{DJI_BASE}/en/Home/CheckLogin'
    cookies_before = cookies_to_string(session.cookies)
    try:
        resp = session.post(
            url,
            data={'UserName': username, 'PassWord': password},
            headers={
                'X-Requested-With': 'XMLHttpRequest',
                'Referer': f'{DJI_BASE}/en/Home/Login',
                'Origin': DJI_BASE,
                'Accept': 'application/json, text/javascript, */*; q=0.01',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            },
            timeout=20,
        )
    except Exception as e:
        return {'ok': False, 'msg': f'request error: {e}'}

    new_cookies = cookies_to_string(session.cookies)
    cookies_all = '; '.join(filter(None, [cookies_before, new_cookies]))

    body = resp.text
    try:
        data = resp.json()
    except Exception:
        data = {}

    state = str(data.get('state') or '')
    if state not in ('1', '2', ''):
        print(f'[DEBUG] unexpected state={state} body={resp.text[:500]} status={resp.status_code}', flush=True)
    is_login = data.get('success') is True or data.get('IsLogin') is True
    is_otp = state == '2'
    is_ok = is_login or state == '1'

    return {
        'ok': is_ok,
        'otp_required': is_otp,
        'cookies': cookies_all,
        'json': data,
        'status': resp.status_code,
        'msg': data.get('msg') or f'state={state or "?"}',
    }


def verify_otp(username, password, otp_code, cookies_str):
    """POST /api/Home/VerifyLoginCode với session cookies."""
    # Restore session cookies
    session.cookies.clear()
    for piece in (cookies_str or '').split(';'):
        piece = piece.strip()
        if '=' in piece:
            name, _, value = piece.partition('=')
            session.cookies.set(name.strip(), value.strip(), domain='.dji.com')

    url = f'{DJI_BASE}/api/Home/VerifyLoginCode'
    try:
        resp = session.post(
            url,
            json={'userName': username, 'password': password, 'verifyCode': otp_code},
            headers={
                'X-Requested-With': 'XMLHttpRequest',
                'Referer': f'{DJI_BASE}/en/Home/Login',
                'Origin': DJI_BASE,
                'Accept': 'application/json, text/javascript, */*; q=0.01',
            },
            timeout=20,
        )
    except Exception as e:
        return {'success': False, 'message': f'request error: {e}'}

    new_cookies = cookies_to_string(session.cookies)
    cookies_all = '; '.join(filter(None, [cookies_str, new_cookies]))

    try:
        data = resp.json()
    except Exception:
        data = {}

    state = str(data.get('state') or '')
    success = data.get('success') is True or state == '1' or resp.status_code < 400

    return {
        'success': success,
        'cookies': cookies_all,
        'json': data,
        'status': resp.status_code,
        'body': resp.text[:300],
    }


def resend_otp(username, password):
    """POST /api/Home/SendLoginCode."""
    url = f'{DJI_BASE}/api/Home/SendLoginCode'
    try:
        resp = session.post(
            url,
            json={'userName': username, 'password': password},
            headers={
                'X-Requested-With': 'XMLHttpRequest',
                'Referer': f'{DJI_BASE}/en/Home/Login',
                'Origin': DJI_BASE,
                'Accept': 'application/json, text/javascript, */*; q=0.01',
            },
            timeout=20,
        )
        try:
            data = resp.json()
        except Exception:
            data = {}
        return {'success': resp.status_code < 400, 'status': resp.status_code, 'json': data, 'body': resp.text[:300]}
    except Exception as e:
        return {'success': False, 'message': str(e)}


@app.route('/health')
def health():
    try:
        ip_resp = requests.get('https://api.ipify.org', timeout=5)
        public_ip = ip_resp.text.strip()
    except Exception:
        public_ip = 'unknown'
    return jsonify({
        'service': 'DJI Login Backend',
        'version': '1.0',
        'public_ip': public_ip,
        'endpoints': ['POST /dji/login', 'POST /dji/otp', 'POST /dji/resend'],
        'time': time.strftime('%Y-%m-%d %H:%M:%S'),
    })


@app.route('/dji/login', methods=['POST'])
def api_login():
    body = request.get_json(silent=True) or {}
    username = (body.get('username') or '').strip()
    password = body.get('password') or ''
    if not username or not password:
        return jsonify({'success': False, 'message': 'username & password required'}), 400

    get_session_cookies()
    result = check_login(username, password)

    print(f'[LOGIN] {username} → success={result["ok"]} otp={result["otp_required"]} state={result["json"].get("state")}', flush=True)

    return jsonify({
        'success': result['ok'] or result['otp_required'],
        'requiresOTP': result['otp_required'],
        'cookies': result['cookies'],
        'endpoint': '/en/Home/CheckLogin',
        'payload': 'UserName+PassWord',
        'contentType': 'form',
        'message': 'Login successful!' if result['ok'] else ('OTP required' if result['otp_required'] else result['msg']),
        'json': result['json'],
        'status': result['status'],
        'backend': 'python-local',
        'raw_body': result['json'].get('body') or '',
        'attempts': [{
            'endpoint': '/en/Home/CheckLogin',
            'contentType': 'form',
            'payload': 'UserName+PassWord',
            **result['json'],
            'status': result['status'],
        }],
    })


@app.route('/dji/otp', methods=['POST'])
def api_otp():
    body = request.get_json(silent=True) or {}
    username = body.get('username') or ''
    password = body.get('password') or ''
    otp_code = body.get('otpCode') or ''
    cookies = body.get('cookies') or ''

    if not otp_code or not cookies:
        return jsonify({'success': False, 'message': 'otpCode & cookies required'}), 400

    result = verify_otp(username, password, otp_code, cookies)
    print(f'[OTP] {username} → success={result["success"]}', flush=True)
    return jsonify(result)


@app.route('/dji/resend', methods=['POST'])
def api_resend():
    body = request.get_json(silent=True) or {}
    username = body.get('username') or ''
    password = body.get('password') or ''
    return jsonify(resend_otp(username, password))


if __name__ == '__main__':
    # Colab/IPython không có sys.stdout.buffer — dùng reconfigure (hỗ trợ từ Python 3.7+)
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except (AttributeError, Exception):
        pass

    port = int(os.environ.get('PORT', 5000))
    print('=' * 60)
    print('  DJI Login Backend')
    print(f'  Running on: http://localhost:{port}')
    print(f'  Endpoints:')
    print(f'    POST http://localhost:{port}/dji/login')
    print(f'    POST http://localhost:{port}/dji/otp')
    print(f'    POST http://localhost:{port}/dji/resend')
    print(f'    GET  http://localhost:{port}/health')
    print(f'=' * 60)
    print(f'  Sau khi chạy, mở terminal khác:')
    print(f'    ngrok http {port}')
    print(f'  Copy URL ngrok vào Settings → ngrok_url trong GAS.')
    print(f'=' * 60)
    app.run(host='0.0.0.0', port=port, debug=False)
