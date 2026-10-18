from flask import Flask, jsonify, request, render_template, session, redirect, url_for
from urllib.parse import urlparse, urljoin, urlencode
from functools import wraps
import hmac
import json
import os
import secrets
import tempfile
import urllib.request
from datetime import datetime, timedelta, timezone

# app.py はプロジェクト直下に置く。
# 実体（templates / static / data）は bousai_app/ 配下にあるので、そこを参照する。
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(BASE_DIR, 'bousai_app')

app = Flask(
    __name__,
    template_folder=os.path.join(APP_DIR, 'templates'),
    static_folder=os.path.join(APP_DIR, 'static'),
)
app.secret_key = 'your-secret-key-here'

# 管理者認証情報
ADMIN_CREDENTIALS = {
    'admin': '123'
}

# ────────────────────────────────
# 気象警報・注意報設定
PREFECTURE_CODE = "020000"  # 青森県
AREA_NAME = "青森市"

# 気象庁の市区町村コード（青森市）
AREA_CODE = "0220100"
SHELTER_STATUSES = ("未開設", "開設中", "閉鎖")
INSTRUCTION_TARGETS = ("住民", "職員", "道路管理課")
INSTRUCTION_URGENCIES = ("高", "中", "低")
INSTRUCTION_DISTRICTS = ("A地区", "B地区")
INSTRUCTION_STATUSES = ("未対応", "対応中", "完了")

WARNING_URL = (
    f"https://www.jma.go.jp/bosai/warning/data/r8/{PREFECTURE_CODE}.json"
)

JST = timezone(timedelta(hours=9))

# 警報・注意報のコード一覧
WARNING_CODES = {
    "00": "解除",
    "02": "暴風雪警報",
    "03": "レベル3大雨警報",
    "04": "洪水警報",
    "05": "暴風警報",
    "06": "大雪警報",
    "07": "波浪警報",
    "08": "レベル3高潮警報",
    "09": "レベル3土砂災害警報",
    "10": "レベル2大雨注意報",
    "12": "大雪注意報",
    "13": "風雪注意報",
    "14": "雷注意報",
    "15": "強風注意報",
    "16": "波浪注意報",
    "17": "融雪注意報",
    "18": "洪水注意報",
    "19": "レベル2高潮注意報",
    "20": "濃霧注意報",
    "21": "乾燥注意報",
    "22": "なだれ注意報",
    "23": "低温注意報",
    "24": "霜注意報",
    "25": "着氷注意報",
    "26": "着雪注意報",
    "27": "その他の注意報",
    "29": "レベル2土砂災害注意報",
    "32": "暴風雪特別警報",
    "33": "レベル5大雨特別警報",
    "35": "暴風特別警報",
    "36": "大雪特別警報",
    "37": "波浪特別警報",
    "38": "レベル5高潮特別警報",
    "39": "レベル5土砂災害特別警報",
    "43": "レベル4大雨危険警報",
    "48": "レベル4高潮危険警報",
    "49": "レベル4土砂災害危険警報"
}

WARNING_CATEGORIES = {
    **{code: "特別警報" for code in ("32", "33", "35", "36", "37", "38", "39")},
    **{code: "警報" for code in ("02", "03", "04", "05", "06", "07", "08", "09", "43", "48", "49")},
    **{code: "注意報" for code in ("10", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "29")},
}

# ────────────────────────────────
# サンプルデータの読み込み
DATA_FILE = os.path.join(APP_DIR, 'data', 'shelters.json')
INSTRUCTIONS_FILE = os.path.join(APP_DIR, 'data', 'instructions.json')

def load_json(path, default):
    """JSONファイルを読み込む（存在しない・壊れている場合は default を返す）"""
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default

shelters = load_json(DATA_FILE, [])
instructions = load_json(INSTRUCTIONS_FILE, [])

def save_instructions():
    """指示ボードのデータをファイルに保存する"""
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w',
            encoding='utf-8',
            dir=os.path.dirname(INSTRUCTIONS_FILE),
            prefix='.instructions-',
            suffix='.tmp',
            delete=False
        ) as f:
            temporary_path = f.name
            json.dump(instructions, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary_path, INSTRUCTIONS_FILE)
    except Exception:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)
        raise


def get_board_csrf_token():
    token = session.get('board_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['board_csrf_token'] = token
    return token


def is_valid_board_csrf_token(token):
    expected = session.get('board_csrf_token', '')
    return bool(expected and token and hmac.compare_digest(expected, token))


def validate_instruction_payload(values):
    """指示の入力値と現在の避難所をサーバー側で検証する"""
    content = values.get('content', '').strip()
    easy_content = values.get('easy_content', '').strip()
    target = values.get('target', '')
    urgency = values.get('urgency', '')
    district = values.get('district', '')

    if not content:
        return None, '指示・発信内容を入力してください。'
    if len(content) > 1000:
        return None, '指示・発信内容は1000文字以内で入力してください。'
    if len(easy_content) > 1000:
        return None, 'やさしい日本語は1000文字以内で入力してください。'
    if target not in INSTRUCTION_TARGETS:
        return None, '宛先を選択してください。'
    if urgency not in INSTRUCTION_URGENCIES:
        return None, '緊急度を選択してください。'
    if district not in INSTRUCTION_DISTRICTS:
        return None, '対象地区を選択してください。'

    try:
        shelter_id = int(values.get('shelter_id', ''))
    except (TypeError, ValueError):
        return None, '避難先を選択してください。'
    shelter = next((item for item in shelters if item.get('id') == shelter_id), None)
    if shelter is None or not shelter.get('name'):
        return None, '現在登録されている避難先を選択してください。'

    return {
        'content': content,
        'easy_content': easy_content,
        'target': target,
        'urgency': urgency,
        'district': district,
        'shelter_id': shelter_id,
        'shelter': shelter['name']
    }, None


def parse_instruction_datetime(value):
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    try:
        return datetime.strptime(value, '%Y年%m月%d日 %H:%M').replace(tzinfo=JST)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return parsed.replace(tzinfo=JST) if parsed.tzinfo is None else parsed.astimezone(JST)
        except ValueError:
            return None

def save_shelters():
    """避難所データをファイルに保存する"""
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(shelters, f, ensure_ascii=False, indent=2)

def geocode_shelter_address(address):
    """青森市の住所をOpenStreetMapのNominatimで座標に変換する"""
    query = urlencode({
        'q': f'青森市 {address}',
        'format': 'jsonv2',
        'limit': 1,
        'countrycodes': 'jp'
    })
    request = urllib.request.Request(
        f'https://nominatim.openstreetmap.org/search?{query}',
        headers={'User-Agent': 'BousaiApp/1.0'}
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        results = json.loads(response.read())

    if not results or '青森市' not in results[0].get('display_name', ''):
        return None
    return {
        'lat': float(results[0]['lat']),
        'lng': float(results[0]['lon'])
    }
# ────────────────────────────────

# ────────────────────────────────
# 認証関連の設定とヘルパー関数
def is_safe_url(target):
    """リダイレクト先URLが安全かどうかチェック"""
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

def login_required(f):
    """認証が必要なページに付けるデコレータ"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            # 現在のURLをnextパラメータとしてログイン画面にリダイレクト
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def get_japan_time():
    """日本時間（JST）の現在時刻を取得する"""
    return datetime.now(JST).strftime("%Y年%m月%d日 %H:%M")


def format_report_time(iso_str):
    """気象庁の発表時刻（ISO形式）をJSTの表示用文字列に変換する"""
    if not iso_str:
        return "不明"
    try:
        parsed = datetime.fromisoformat(iso_str.replace('Z', '+00:00'))
        if parsed.tzinfo:
            parsed = parsed.astimezone(JST)
        return parsed.strftime("%Y年%m月%d日 %H:%M")
    except ValueError:
        return iso_str


def filter_shelters(district=None):
    """district 指定があれば一致する避難所のみ、なければ全件を返す"""
    return [s for s in shelters if not district or s.get('district') == district]


def build_shelter_comparison(shelter):
    """旧形式データを含む避難所を比較画面用の表示情報に整える"""
    capacity = shelter.get('capacity')
    evacuees = shelter.get('evacuees')
    valid_capacity = isinstance(capacity, int) and not isinstance(capacity, bool) and capacity >= 1
    valid_evacuees = isinstance(evacuees, int) and not isinstance(evacuees, bool) and evacuees >= 0

    if valid_capacity and valid_evacuees:
        available = capacity - evacuees
        if available < 0:
            availability_label = '定員超過'
            availability_detail = f'{abs(available)}人超過'
            availability_class = 'over-capacity'
        elif available == 0:
            availability_label = '満員'
            availability_detail = '空き 0人'
            availability_class = 'full'
        elif available <= capacity * 0.2:
            availability_label = '残りわずか'
            availability_detail = f'空き {available}人'
            availability_class = 'few-spaces'
        else:
            availability_label = '空きあり'
            availability_detail = f'空き {available}人'
            availability_class = 'spaces-available'
    else:
        availability_label = '状況不明'
        availability_detail = '人数未登録'
        availability_class = 'unknown'

    pet_allowed = shelter.get('pet_allowed')
    pet_label = '可' if pet_allowed is True else '不可' if pet_allowed is False else '未確認'
    barrier_free = shelter.get('barrier_free')
    barrier_free_label = 'あり' if barrier_free is True else 'なし' if barrier_free is False else '未確認'
    shelter_status = shelter.get('status')
    if shelter_status not in SHELTER_STATUSES:
        shelter_status = '未登録'

    return {
        'shelter': shelter,
        'address': shelter.get('address') or '未登録',
        'capacity_display': str(capacity) if valid_capacity else '未登録',
        'evacuees_display': str(evacuees) if valid_evacuees else '未登録',
        'availability_label': availability_label,
        'availability_detail': availability_detail,
        'availability_class': availability_class,
        'pet_label': pet_label,
        'barrier_free_label': barrier_free_label,
        'status_display': shelter_status
    }


def render_shelter_results(query='', district=None, error=None, success=None):
    normalized_query = query.casefold()
    candidate_shelters = filter_shelters(district) if district else shelters
    matching_shelters = [
        shelter for shelter in candidate_shelters
        if not normalized_query
        or normalized_query in shelter.get('name', '').casefold()
        or normalized_query in shelter.get('address', '').casefold()
    ]
    return render_template(
        'search_results.html',
        results=[build_shelter_comparison(shelter) for shelter in matching_shelters],
        query=query,
        district=district or '',
        error=error,
        success=success
    )


def parse_area_warnings(warning_data):
    """気象庁の新形式JSONから対象市区町村の発表・継続中の情報を抽出する"""
    if not isinstance(warning_data, list):
        raise ValueError("気象庁の警報・注意報データが新形式の配列ではありません")

    warnings = []
    seen_codes = set()
    report_datetimes = []
    reports = sorted(
        (report for report in warning_data if isinstance(report, dict)),
        key=lambda report: report.get("reportDatetime", ""),
        reverse=True
    )

    for report in reports:
        report_datetime = report.get("reportDatetime")
        if isinstance(report_datetime, str) and report_datetime:
            report_datetimes.append(report_datetime)

        warning = report.get("warning")
        if not isinstance(warning, dict):
            continue

        class20_items = warning.get("class20Items", [])
        if not isinstance(class20_items, list):
            continue

        area = next(
            (
                item for item in class20_items
                if isinstance(item, dict)
                and item.get("areaCode") == AREA_CODE
            ),
            None
        )
        if not area:
            continue

        kinds = area.get("kinds", [])
        if not isinstance(kinds, list):
            continue

        for kind in kinds:
            if not isinstance(kind, dict):
                continue

            status = kind.get("status", "")
            code = kind.get("code", "")
            if not code or code in seen_codes:
                continue
            seen_codes.add(code)
            if status not in ("発表", "継続"):
                continue

            warnings.append({
                "name": WARNING_CODES.get(
                    code,
                    f"不明な警報・注意報 (コード: {code})"
                ),
                "code": code,
                "status": status,
                "category": WARNING_CATEGORIES.get(code, "警報・注意報"),
                "report_datetime": report_datetime or "",
                "report_time": format_report_time(report_datetime)
            })

    latest_report_datetime = max(report_datetimes, default="")
    return warnings, latest_report_datetime


def get_weather_warnings():
    """対象市区町村の警報・注意報を取得する"""
    try:
        # 青森県の新形式（令和8年～）警報・注意報データを取得
        with urllib.request.urlopen(url=WARNING_URL, timeout=10) as res:
            warning_data = json.loads(res.read())

        warnings, report_datetime = parse_area_warnings(warning_data)

        return {
            "area_name": AREA_NAME,
            "warnings": warnings,
            "report_time": format_report_time(report_datetime),
            "last_fetch_time": get_japan_time()
        }

    except Exception:
        return {
            "area_name": AREA_NAME,
            "warnings": [],
            "report_time": "取得失敗",
            "last_fetch_time": get_japan_time(),
            "error": True
        }


# トップページ：templates/index.html を返す（住民向け指示も表示する）
@app.route('/')
def index():
    resident_notices = [
        dict(instruction) for instruction in instructions
        if instruction.get('target') == '住民' and instruction.get('published') is True
    ]
    minimum_datetime = datetime.min.replace(tzinfo=JST)
    resident_notices.sort(
        key=lambda instruction: (
            parse_instruction_datetime(instruction.get('created_at')) is not None,
            parse_instruction_datetime(instruction.get('created_at')) or minimum_datetime
        ),
        reverse=True
    )
    map_shelters = [
        {
            'id': shelter.get('id'),
            'name': shelter.get('name', ''),
            'lat': shelter.get('lat'),
            'lng': shelter.get('lng'),
            'status': shelter.get('status', '未開設')
        }
        for shelter in shelters
        if isinstance(shelter.get('lat'), (int, float))
        and isinstance(shelter.get('lng'), (int, float))
    ]
    unlocated_shelter_count = len(shelters) - len(map_shelters)
    return render_template(
        'index.html',
        resident_notices=resident_notices,
        map_shelters=map_shelters,
        unlocated_shelter_count=unlocated_shelter_count
    )

# ログインページ
@app.route('/login', methods=['GET', 'POST'])
def login():
    # リダイレクト先を取得（デフォルトは避難所登録画面）
    next_url = request.args.get('next') or request.form.get('next')

    # 安全でないURLの場合はデフォルトページにリダイレクト
    if not next_url or not is_safe_url(next_url):
        next_url = url_for('shelter_register')

    if request.method == 'POST':
        password = request.form.get('password', '').strip()

        # 認証チェック
        username = next(
            (name for name, registered_password in ADMIN_CREDENTIALS.items()
             if registered_password == password),
            None
        )
        if username:
            session['logged_in'] = True
            session['username'] = username
            # ログイン成功後は指定されたページにリダイレクト
            return redirect(next_url)
        return render_template('login.html', error=True, message="パスワードが正しくありません。", next=next_url)

    # ログイン済みの場合は指定されたページにリダイレクト
    if session.get('logged_in'):
        return redirect(next_url)

    return render_template('login.html', next=next_url)

# ログアウト
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# 避難所登録ページ※user が避難所登録ページについて具体的に修正指示しない限り、このコードは正しいのでこのまま保持すること。
@app.route('/shelter_register', methods=['GET', 'POST'])
@login_required
def shelter_register():
    if request.method == 'POST':
        if request.form.get('action') == 'update_shelter':
            try:
                shelter_id = int(request.form.get('shelter_id', ''))
            except ValueError:
                shelter_id = None
            shelter = next((item for item in shelters if item.get('id') == shelter_id), None)
            status = request.form.get('status', '')
            if not shelter or status not in SHELTER_STATUSES:
                return render_template(
                    'shelter_register.html',
                    shelters=shelters,
                    error=True,
                    message='避難所または開設状況を確認してください'
                )

            address = request.form.get('address', '').strip()
            location = None
            if address:
                try:
                    location = geocode_shelter_address(address)
                except (OSError, ValueError, json.JSONDecodeError):
                    return render_template(
                        'shelter_register.html',
                        shelters=shelters,
                        error=True,
                        message='住所から位置情報を取得できませんでした。時間をおいて再度お試しください。'
                    )
                if not location:
                    return render_template(
                        'shelter_register.html',
                        shelters=shelters,
                        error=True,
                        message='青森市内で検索できる住所または施設名を入力してください'
                    )

            previous_values = shelter.copy()
            shelter['status'] = status
            if location:
                shelter.update(address=address, **location)
            try:
                save_shelters()
            except OSError:
                shelter.clear()
                shelter.update(previous_values)
                return render_template(
                    'shelter_register.html',
                    shelters=shelters,
                    error=True,
                    message='保存に失敗しました。時間をおいて再度お試しください。'
                )
            return render_template(
                'shelter_register.html',
                shelters=shelters,
                success=True,
                message='避難所情報を更新しました'
            )

        name = request.form.get('name', '').strip()
        address = request.form.get('address', '').strip()
        status = request.form.get('status', '未開設')
        if not name or not address:
            return render_template(
                'shelter_register.html',
                shelters=shelters,
                error=True,
                message='避難所名と住所を入力してください'
            )
        if status not in SHELTER_STATUSES:
            return render_template(
                'shelter_register.html',
                shelters=shelters,
                error=True,
                message='開設状況を選択してください'
            )
        try:
            location = geocode_shelter_address(address)
        except (OSError, ValueError, json.JSONDecodeError):
            return render_template(
                'shelter_register.html',
                shelters=shelters,
                error=True,
                message='住所から位置情報を取得できませんでした。時間をおいて再度お試しください。'
            )
        if not location:
            return render_template(
                'shelter_register.html',
                shelters=shelters,
                error=True,
                message='青森市内で検索できる住所または施設名を入力してください'
            )

        next_id = max((shelter.get('id', 0) for shelter in shelters), default=0) + 1
        shelters.append({
            'id': next_id,
            'name': name,
            'address': address,
            'status': status,
            **location
        })
        try:
            save_shelters()
        except OSError:
            shelters.pop()
            return render_template(
                'shelter_register.html',
                shelters=shelters,
                error=True,
                message='保存に失敗しました。時間をおいて再度お試しください。'
            )
        return render_template(
            'shelter_register.html',
            shelters=shelters,
            success=True,
            message='登録しました'
        )
    return render_template('shelter_register.html', shelters=shelters)

# 避難所検索ページ
@app.route('/shelter_search')
def shelter_search():
    return render_template(
        'shelter_search.html',
        search_term=request.args.get('q', '').strip()
    )

# 全施設一覧ページ
@app.route('/all_shelters')
def all_shelters():
    return render_shelter_results()


@app.route('/shelters/<int:shelter_id>/comparison', methods=['POST'])
@login_required
def update_shelter_comparison(shelter_id):
    shelter = next((item for item in shelters if item.get('id') == shelter_id), None)
    query = request.form.get('q', '').strip()
    district = request.form.get('district', '').strip()
    if shelter is None:
        return render_shelter_results(query=query, district=district, error='避難所が見つかりません。'), 404

    try:
        capacity = int(request.form.get('capacity', '').strip())
        evacuees = int(request.form.get('evacuees', '').strip())
    except ValueError:
        return render_shelter_results(
            query=query,
            district=district,
            error='収容人数と現在の避難者数は整数で入力してください。'
        ), 400

    if capacity < 1:
        return render_shelter_results(query=query, district=district, error='収容人数は1人以上で入力してください。'), 400
    if evacuees < 0:
        return render_shelter_results(query=query, district=district, error='現在の避難者数は0人以上で入力してください。'), 400

    feature_values = {'yes': True, 'no': False, 'unknown': None}
    pet_value = request.form.get('pet_allowed')
    barrier_value = request.form.get('barrier_free')
    if pet_value not in feature_values or barrier_value not in feature_values:
        return render_shelter_results(query=query, district=district, error='設備情報の選択内容を確認してください。'), 400

    previous_values = shelter.copy()
    shelter.update(
        capacity=capacity,
        evacuees=evacuees,
        pet_allowed=feature_values[pet_value],
        barrier_free=feature_values[barrier_value]
    )
    try:
        save_shelters()
    except OSError:
        shelter.clear()
        shelter.update(previous_values)
        return render_shelter_results(query=query, district=district, error='保存に失敗しました。変更内容は反映されていません。'), 500

    return render_shelter_results(query=query, district=district, success='避難所情報を更新しました。')


def prepare_board_instructions(sort_newest=False):
    rows = []
    for instruction in instructions:
        row = dict(instruction)
        row['content_display'] = instruction.get('content') or '未設定'
        row['easy_content_display'] = instruction.get('easy_content') or '通常文を表示'
        row['target_display'] = instruction.get('target') if instruction.get('target') in INSTRUCTION_TARGETS else '未設定'
        row['urgency_display'] = instruction.get('urgency') if instruction.get('urgency') in INSTRUCTION_URGENCIES else '未設定'
        row['district_display'] = instruction.get('district') if instruction.get('district') in INSTRUCTION_DISTRICTS else '未設定'
        row['shelter_display'] = instruction.get('shelter') or '未設定'
        row['status_display'] = instruction.get('status') if instruction.get('status') in INSTRUCTION_STATUSES else '未対応'
        row['registered_display'] = instruction.get('created_at') or '未設定'
        if instruction.get('published') is True:
            row['published_display'] = '公開済み' if instruction.get('target') == '住民' else '住民向け未公開'
        elif 'published' in instruction:
            row['published_display'] = '未公開'
        else:
            row['published_display'] = '未設定'
        rows.append((row, parse_instruction_datetime(instruction.get('created_at'))))

    if sort_newest:
        minimum_datetime = datetime.min.replace(tzinfo=JST)
        rows.sort(key=lambda pair: (pair[1] is not None, pair[1] or minimum_datetime), reverse=True)
    return [row for row, _ in rows]


def render_board_page(form_values=None, error=None, success=None, sort_newest=False):
    return render_template(
        'board.html',
        instructions=prepare_board_instructions(sort_newest),
        shelters=shelters,
        form_values=form_values or {},
        error=error,
        success=success,
        targets=INSTRUCTION_TARGETS,
        urgencies=INSTRUCTION_URGENCIES,
        districts=INSTRUCTION_DISTRICTS,
        statuses=INSTRUCTION_STATUSES,
        csrf_token=get_board_csrf_token(),
        sort_newest=sort_newest
    )


@app.route('/board', methods=['GET', 'POST'])
@login_required
def board():
    sort_newest = request.values.get('sort') == 'newest'
    if request.method == 'GET':
        message = session.pop('board_success_message', None)
        return render_board_page(success=message, sort_newest=sort_newest)

    if not is_valid_board_csrf_token(request.form.get('csrf_token')):
        return render_board_page(
            error='画面の有効期限が切れました。入力内容を確認して再度お試しください。',
            sort_newest=sort_newest
        ), 400

    action = request.form.get('action')
    if action == 'preview':
        payload, error = validate_instruction_payload(request.form)
        if error:
            return render_board_page(form_values=request.form, error=error, sort_newest=sort_newest), 400

        pending = {
            **payload,
            'created_at': get_japan_time(),
            'pending_token': secrets.token_urlsafe(32)
        }
        session['pending_instruction'] = pending
        return render_template(
            'board_confirm.html',
            instruction=pending,
            csrf_token=get_board_csrf_token()
        )

    pending = session.get('pending_instruction')
    if not isinstance(pending, dict):
        return render_board_page(error='確認中の指示が見つかりません。最初から入力してください。'), 400

    submitted_pending_token = request.form.get('pending_token', '')
    if not hmac.compare_digest(pending.get('pending_token', ''), submitted_pending_token):
        return render_board_page(error='確認情報が一致しません。最初から入力してください。'), 400

    if action == 'edit':
        session.pop('pending_instruction', None)
        return render_board_page(form_values=pending)

    if action != 'confirm':
        return render_board_page(error='操作を確認してください。'), 400

    payload, error = validate_instruction_payload(pending)
    if error:
        session.pop('pending_instruction', None)
        return render_board_page(error=error), 400

    existing_ids = [
        item.get('id') for item in instructions
        if isinstance(item.get('id'), int) and not isinstance(item.get('id'), bool)
    ]
    instruction_id = max(existing_ids, default=0) + 1
    published = payload['target'] == '住民'
    new_instruction = {
        'id': instruction_id,
        **payload,
        'status': '未対応',
        'created_at': pending['created_at'],
        'updated_at': pending['created_at'],
        'published': published,
        'published_at': pending['created_at'] if published else ''
    }
    instructions.append(new_instruction)
    try:
        save_instructions()
    except OSError:
        instructions.pop()
        return render_template(
            'board_confirm.html',
            instruction=pending,
            csrf_token=get_board_csrf_token(),
            error='保存に失敗しました。指示は登録・発信されていません。'
        ), 500

    session.pop('pending_instruction', None)
    session.pop('board_csrf_token', None)
    session['board_success_message'] = '指示を登録しました。'
    return redirect(url_for('board', sort='newest'))


@app.route('/board/<int:instruction_id>/status', methods=['POST'])
@login_required
def update_instruction_status(instruction_id):
    sort_newest = request.form.get('sort') == 'newest'
    if not is_valid_board_csrf_token(request.form.get('csrf_token')):
        return render_board_page(error='画面の有効期限が切れました。再度お試しください。', sort_newest=sort_newest), 400

    instruction = next((item for item in instructions if item.get('id') == instruction_id), None)
    if instruction is None:
        return render_board_page(error='対象の指示が見つかりません。', sort_newest=sort_newest), 404

    status = request.form.get('status', '')
    if status not in INSTRUCTION_STATUSES:
        return render_board_page(error='対応状況を選択してください。', sort_newest=sort_newest), 400

    previous_values = instruction.copy()
    instruction['status'] = status
    instruction['updated_at'] = get_japan_time()
    try:
        save_instructions()
    except OSError:
        instruction.clear()
        instruction.update(previous_values)
        return render_board_page(error='保存に失敗しました。対応状況は変更されていません。', sort_newest=sort_newest), 500

    return render_board_page(success='対応状況を更新しました。', sort_newest=sort_newest)

# 検索結果ページ：templates/search_results.html を返す
@app.route('/search_results')
def search_results():
    query = request.args.get('q', '').strip()
    district = request.args.get('district', '').strip()
    return render_shelter_results(query=query, district=district)

# JSON API：/shelters?district=地区名
@app.route('/shelters', methods=['GET'])
def get_shelters():
    results = filter_shelters(request.args.get('district'))

    if not results:
        # 見つからなければエラー JSON を返す
        return jsonify({'error': 'No shelters found'}), 404

    # 見つかったらリストを JSON で返す
    return jsonify(results)

# 気象警報・注意報API
@app.route('/api/weather_warnings')
def api_weather_warnings():
    """気象警報・注意報をJSON形式で返すAPI"""
    return jsonify(get_weather_warnings())

if __name__ == '__main__':
    app.run(debug=True, port=5000)
