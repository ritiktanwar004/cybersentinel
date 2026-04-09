"""
CyberSentinel Backend — Flask + SQLite + ML + Free AI
Run: python app.py
API runs on http://localhost:5000
"""

from __future__ import annotations
import json, re, sqlite3, time, os, hashlib
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, request, jsonify, send_from_directory

# ── optional joblib import ──
try:
    import joblib
    import numpy as np
    RF_AVAILABLE = True
except ImportError:
    RF_AVAILABLE = False

# ── optional requests for free AI ──
try:
    import urllib.request as ureq
    import urllib.error
    REQUESTS_AVAILABLE = True
except:
    REQUESTS_AVAILABLE = False

# ════════════════════════════════════════
#  PATHS
# ════════════════════════════════════════
BASE_DIR   = Path(__file__).parent.parent
ML_DIR     = BASE_DIR / "ml"
FRONTEND   = BASE_DIR / "frontend"
DB_PATH    = BASE_DIR / "backend" / "cybersentinel.db"
MODEL_PATH = ML_DIR / "rf_model.pkl"
WEIGHTS    = ML_DIR / "model_weights.json"

app = Flask(__name__, static_folder=str(FRONTEND), static_url_path="")

# ════════════════════════════════════════
#  DATABASE SETUP
# ════════════════════════════════════════
def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS scans (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        url         TEXT NOT NULL,
        url_hash    TEXT NOT NULL,
        verdict     TEXT NOT NULL,
        risk_score  REAL NOT NULL,
        ml_score    REAL,
        lr_score    REAL,
        features    TEXT,
        ai_analysis TEXT,
        ip_address  TEXT,
        created_at  TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_url_hash ON scans(url_hash);
    CREATE INDEX IF NOT EXISTS idx_verdict  ON scans(verdict);
    CREATE INDEX IF NOT EXISTS idx_created  ON scans(created_at);

    CREATE TABLE IF NOT EXISTS stats (
        key   TEXT PRIMARY KEY,
        value INTEGER DEFAULT 0
    );
    INSERT OR IGNORE INTO stats VALUES ('total_scans', 0);
    INSERT OR IGNORE INTO stats VALUES ('phishing_found', 0);
    INSERT OR IGNORE INTO stats VALUES ('safe_found', 0);
    INSERT OR IGNORE INTO stats VALUES ('suspicious_found', 0);
    """)
    conn.commit()
    conn.close()

init_db()

# ════════════════════════════════════════
#  LOAD ML MODEL
# ════════════════════════════════════════
RF_MODEL = None
WEIGHTS_DATA = None
RF_ENABLED = True

if RF_AVAILABLE and MODEL_PATH.exists():
    try:
        RF_MODEL = joblib.load(str(MODEL_PATH))
        print(f"[ML] RF model loaded — acc={RF_MODEL.get('accuracy','?')}")
    except Exception as e:
        print(f"[ML] RF load failed: {e}")

if WEIGHTS.exists():
    with open(WEIGHTS) as f:
        WEIGHTS_DATA = json.load(f)
    print(f"[ML] LR weights loaded — acc={WEIGHTS_DATA.get('accuracy','?')}")


def get_rf_state():
    available = RF_MODEL is not None
    enabled = bool(RF_ENABLED and available)
    return {
        'rf_available': available,
        'rf_enabled': enabled,
        'rf_requested': bool(RF_ENABLED),
    }

# ════════════════════════════════════════
#  FEATURE EXTRACTION (must match training)
# ════════════════════════════════════════
SUSPICIOUS_KW = [
    'login','verify','secure','account','update','confirm','bank','paypal',
    'apple','amazon','google','microsoft','password','credential','suspend',
    'urgent','free','prize','winner','claim','signin','billing','support',
    'security','alert','notice','limited','expire','validate','authenticate'
]
TRUSTED_DOMAINS = [
    'google.com','facebook.com','microsoft.com','apple.com','amazon.com',
    'paypal.com','twitter.com','github.com','linkedin.com','youtube.com',
    'wikipedia.org','reddit.com','instagram.com','netflix.com','ebay.com'
]
TRUSTED_HOSTS = {
    'www.snapchat.com',
    'snapchat.com',
    'google.com',
    'youtube.com',
    'facebook.com',
    'instagram.com',
    'twitter.com',
    'linkedin.com',
    'github.com',
    'stackoverflow.com',
    'wikipedia.org',
    'amazon.com',
    'amazon.in',
    'flipkart.com',
    'myntra.com',
    'apple.com',
    'microsoft.com',
    'netflix.com',
    'paypal.com',
    'openai.com',
    'bing.com',
    'yahoo.com',
    'reddit.com',
    'quora.com',
    'bbc.com',
    'cnn.com',
    'nytimes.com',
    'theguardian.com',
    'ndtv.com',
    'thehindu.com',
    'coursera.org',
    'udemy.com',
    'khanacademy.org',
    'edx.org',
    'zoom.us',
    'slack.com',
    'dropbox.com',
    'drive.google.com',
    'docs.google.com',
    'notion.so',
    'canva.com',
    'adobe.com',
    'shopify.com',
    'wordpress.com',
    'medium.com',
    'airbnb.com',
    'uber.com',
    'ola.com',
    'zomato.com',
    'swiggy.com',
    'paytm.com',
    'phonepe.com',
    'razorpay.com',
    'hdfcbank.com',
    'icicibank.com',
    'sbi.co.in',
}
PHISHING_TLDS = ['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.club',
                 '.online','.site','.info','.biz','.pw','.cc','.su']

def get_host(url: str) -> str:
    try:
        parsed = urlparse(url if url.startswith('http') else 'https://' + url)
        return parsed.netloc.lower().split(':')[0]
    except Exception:
        return ''

def is_trusted_host(url: str) -> bool:
    return get_host(url) in TRUSTED_HOSTS

def extract_features(url: str):
    url = str(url).strip()
    try:
        parsed = urlparse(url if url.startswith('http') else 'https://' + url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()
        query  = parsed.query
    except:
        domain = url.lower(); path = ''; query = ''

    url_lower = url.lower()
    feats = {}
    feats['is_https']       = 1 if url.startswith('https://') else 0
    feats['url_length']     = min(len(url), 200) / 200
    feats['domain_length']  = min(len(domain), 100) / 100
    feats['is_ip']          = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain.split(':')[0]) else 0
    feats['hyphen_count']   = min(domain.count('-'), 10) / 10
    feats['dot_count']      = min(domain.count('.'), 8) / 8
    feats['subdomain_count']= min(max(len(domain.split('.')) - 2, 0), 5) / 5
    feats['suspicious_tld'] = 1 if any(domain.endswith(t) for t in PHISHING_TLDS) else 0
    kw = sum(1 for k in SUSPICIOUS_KW if k in url_lower)
    feats['keyword_count']  = min(kw, 10) / 10
    brand = next((td.split('.')[0] for td in TRUSTED_DOMAINS
                  if td.split('.')[0] in url_lower and not domain.endswith(td)), None)
    feats['brand_mismatch'] = 1 if brand else 0
    feats['at_symbol']      = 1 if '@' in url else 0
    feats['double_slash']   = 1 if '//' in path else 0
    feats['encoded_chars']  = min(len(re.findall(r'%[0-9a-fA-F]{2}', url)), 10) / 10
    feats['digit_ratio']    = sum(c.isdigit() for c in domain) / max(len(domain), 1)
    feats['path_length']    = min(len(path), 150) / 150
    feats['has_port']       = 1 if ':' in domain and domain.split(':')[-1].isdigit() else 0
    feats['has_query']      = 1 if query else 0
    feats['special_chars']  = min(len(re.findall(r"[!$&'()*+,;=]", url)), 10) / 10

    # human-readable extras (not in training, for display)
    extras = {
        'domain': domain,
        'kw_count': kw,
        'brand_spoofed': brand,
        'raw_url_len': len(url),
        'raw_domain_len': len(domain),
    }
    return feats, extras

def logistic_sigmoid(x):
    return 1 / (1 + pow(2.718281828, -x))

def predict_lr(feature_vec: list) -> float:
    """Run LR inference using exported weights."""
    if not WEIGHTS_DATA:
        return 0.5
    mean  = WEIGHTS_DATA['mean']
    scale = WEIGHTS_DATA['scale']
    coef  = WEIGHTS_DATA['coef']
    intercept = WEIGHTS_DATA['intercept']
    scaled = [(feature_vec[i] - mean[i]) / max(scale[i], 1e-9) for i in range(len(feature_vec))]
    logit  = sum(coef[i] * scaled[i] for i in range(len(scaled))) + intercept
    return logistic_sigmoid(logit)

def predict_rf(feature_vec: list) -> float:
    """Run RF inference using sklearn model."""
    if not RF_AVAILABLE or not RF_MODEL or not RF_ENABLED:
        return None
    try:
        model = RF_MODEL['model']
        X = np.array([feature_vec])
        prob = float(model.predict_proba(X)[0][1])
        return prob
    except Exception as e:
        print(f"[RF] predict error: {e}")
        return None

def ensemble_predict(url: str):
    if is_trusted_host(url):
        feats, extras = extract_features(url)
        indicators = build_indicators(feats, extras, url)
        return {
            'verdict': 'legitimate',
            'risk_score': 0.0,
            'ml_score': 0.0,
            'lr_score': 0.0,
            'features': feats,
            'extras': extras,
            'indicators': indicators,
        }

    feats, extras = extract_features(url)
    feat_names = WEIGHTS_DATA['feature_names'] if WEIGHTS_DATA else list(feats.keys())
    feat_vec = [feats.get(n, 0) for n in feat_names]

    lr_prob = predict_lr(feat_vec)
    rf_prob = predict_rf(feat_vec)

    # Ensemble: if RF available weight 60/40, else use LR only
    if rf_prob is not None:
        final_prob = 0.6 * rf_prob + 0.4 * lr_prob
    else:
        final_prob = lr_prob

    risk_score = round(final_prob * 100, 1)

    if risk_score >= 60:
        verdict = "phishing"
    elif risk_score >= 30:
        verdict = "suspicious"
    else:
        verdict = "legitimate"

    # Build indicator list for frontend
    indicators = build_indicators(feats, extras, url)

    return {
        'verdict': verdict,
        'risk_score': risk_score,
        'ml_score': round(rf_prob * 100, 1) if rf_prob else None,
        'lr_score': round(lr_prob * 100, 1),
        'features': feats,
        'extras': extras,
        'indicators': indicators,
    }

def build_indicators(feats, extras, url):
    ind = []
    ind.append({'label': 'HTTPS Encryption',
                'value': 'Enabled' if feats['is_https'] else 'Missing',
                'status': 'safe' if feats['is_https'] else 'warn'})
    ind.append({'label': 'IP Address Domain',
                'value': 'Detected ⚠' if feats['is_ip'] else 'Clean',
                'status': 'danger' if feats['is_ip'] else 'safe'})
    ind.append({'label': 'Suspicious TLD',
                'value': 'Detected ⚠' if feats['suspicious_tld'] else 'Clean',
                'status': 'danger' if feats['suspicious_tld'] else 'safe'})
    kc = extras['kw_count']
    ind.append({'label': 'Phishing Keywords',
                'value': f'{kc} found',
                'status': 'danger' if kc > 3 else 'warn' if kc > 1 else 'safe'})
    ind.append({'label': 'Brand Spoofing',
                'value': f'⚠ {extras["brand_spoofed"]}' if extras['brand_spoofed'] else 'None',
                'status': 'danger' if extras['brand_spoofed'] else 'safe'})
    h = round(feats['hyphen_count'] * 10)
    ind.append({'label': 'Hyphens in Domain',
                'value': f'{h} found',
                'status': 'danger' if h > 2 else 'warn' if h > 0 else 'safe'})
    s = round(feats['subdomain_count'] * 5)
    ind.append({'label': 'Subdomain Depth',
                'value': f'{s} levels',
                'status': 'danger' if s > 2 else 'warn' if s > 1 else 'safe'})
    ul = extras['raw_url_len']
    ind.append({'label': 'URL Length',
                'value': f'{ul} chars',
                'status': 'danger' if ul > 100 else 'warn' if ul > 60 else 'safe'})
    ind.append({'label': 'Encoded Characters',
                'value': 'Present ⚠' if feats['encoded_chars'] > 0 else 'None',
                'status': 'warn' if feats['encoded_chars'] > 0 else 'safe'})
    ind.append({'label': '@ Symbol',
                'value': 'Found ⚠' if feats['at_symbol'] else 'None',
                'status': 'danger' if feats['at_symbol'] else 'safe'})
    return ind

# ════════════════════════════════════════
#  FREE AI ANALYSIS  (Hugging Face Inference API — no key needed for many models)
# ════════════════════════════════════════

def get_free_ai_analysis(url: str, verdict: str, risk_score: float, extras: dict) -> str:
    """
    Uses Hugging Face's free inference API with a text-generation model.
    Falls back to rule-based analysis if network unavailable.
    """
    prompt = f"""[INST] You are a cybersecurity expert. Analyze this URL for phishing threats.

URL: {url}
Domain: {extras.get('domain','?')}
ML Risk Score: {risk_score}/100
Verdict: {verdict.upper()}
Brand Spoofing: {extras.get('brand_spoofed') or 'None'}
Phishing Keywords Found: {extras.get('kw_count',0)}

Give a 3-sentence security assessment: (1) threat verdict, (2) key risk indicators, (3) recommended action. Be direct and professional. [/INST]"""

    try:
        data = json.dumps({"inputs": prompt, "parameters": {"max_new_tokens": 200, "temperature": 0.3}}).encode()
        req = ureq.Request(
            "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.1",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with ureq.urlopen(req, timeout=8) as resp:
            result = json.loads(resp.read())
            if isinstance(result, list) and result:
                text = result[0].get('generated_text', '')
                # Strip the prompt if echoed back
                if '[/INST]' in text:
                    text = text.split('[/INST]')[-1].strip()
                return text[:600]
    except Exception as e:
        print(f"[AI] Free AI unavailable: {e}")

    # ── RULE-BASED FALLBACK ──
    return generate_rule_based_analysis(url, verdict, risk_score, extras)


def generate_rule_based_analysis(url, verdict, risk_score, extras):
    """Smart rule-based analysis that mimics AI reasoning."""
    domain = extras.get('domain', '?')
    kw = extras.get('kw_count', 0)
    brand = extras.get('brand_spoofed')

    lines = []
    if verdict == 'phishing':
        lines.append(f"HIGH THREAT DETECTED: This URL exhibits multiple phishing indicators with a risk score of {risk_score}/100, strongly suggesting a credential-harvesting or malware delivery attempt.")
        reasons = []
        if brand:
            reasons.append(f"brand impersonation of '{brand}'")
        if kw > 0:
            reasons.append(f"{kw} social engineering keywords")
        if extras.get('is_ip'):
            reasons.append("IP address used as domain (bypasses DNS trust)")
        if extras.get('suspicious_tld'):
            reasons.append("known high-abuse TLD (.tk/.xyz/.ml etc.)")
        if reasons:
            lines.append(f"Critical indicators: {', '.join(reasons)}.")
        lines.append("RECOMMENDATION: Do NOT visit this URL. Do not enter credentials. Report it to your IT/security team immediately.")

    elif verdict == 'suspicious':
        lines.append(f"CAUTION: This URL scored {risk_score}/100 on threat indicators, placing it in the suspicious category — proceed only with verification.")
        if kw > 0:
            lines.append(f"Found {kw} sensitive keyword(s) that commonly appear in social engineering attacks; the domain '{domain}' should be independently verified.")
        else:
            lines.append(f"The domain '{domain}' has structural anomalies that match known phishing patterns, though no definitive threat markers were found.")
        lines.append("RECOMMENDATION: Verify this URL through an independent source before clicking. If received via email or message, treat as potentially malicious.")

    else:
        lines.append(f"LOW RISK: This URL scored {risk_score}/100 and passes standard phishing heuristics — it appears to be a legitimate web address.")
        lines.append(f"The domain '{domain}' uses proper HTTPS, standard structure, and contains no known phishing indicators or brand spoofing patterns.")
        lines.append("RECOMMENDATION: While appearing safe, always verify unexpected links. Even legitimate-looking URLs can be compromised — when in doubt, navigate directly.")

    return " ".join(lines)

# ════════════════════════════════════════
#  CORS MIDDLEWARE
# ════════════════════════════════════════
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin']  = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    return response

@app.route('/api/<path:p>', methods=['OPTIONS'])
def options_handler(p):
    return '', 204

# ════════════════════════════════════════
#  API ROUTES
# ════════════════════════════════════════

@app.route('/api', methods=['GET'])
@app.route('/api/', methods=['GET'])
def api_index():
    return jsonify({
        'name': 'CyberSentinel API',
        'status': 'ok',
        'version': '1.0',
        'endpoints': {
            'predict': '/api/predict',
            'bulk': '/api/bulk',
            'history': '/api/history',
            'stats': '/api/stats',
            'model_info': '/api/model-info',
            'model_control': '/api/model-control',
            'search': '/api/search?q=<query>'
        }
    })


@app.route('/api/model-control', methods=['GET'])
def api_model_control_get():
    return jsonify(get_rf_state())


@app.route('/api/model-control', methods=['POST'])
def api_model_control_post():
    global RF_ENABLED
    body = request.get_json(silent=True) or {}
    if 'rf_enabled' not in body:
        return jsonify({'error': 'rf_enabled boolean is required'}), 400

    requested = bool(body.get('rf_enabled'))
    if requested and RF_MODEL is None:
        RF_ENABLED = False
        state = get_rf_state()
        return jsonify({
            'error': 'Random Forest model file not loaded',
            **state,
        }), 400

    RF_ENABLED = requested
    return jsonify(get_rf_state())

@app.route('/api/predict', methods=['POST'])
def api_predict():
    body = request.get_json(silent=True) or {}
    url  = str(body.get('url', '')).strip()
    if not url:
        return jsonify({'error': 'url is required'}), 400

    normalized = url if url.startswith('http') else 'https://' + url
    url_hash   = hashlib.md5(normalized.encode()).hexdigest()

    # Run ML
    result = ensemble_predict(normalized)
    verdict     = result['verdict']
    risk_score  = result['risk_score']
    indicators  = result['indicators']
    extras      = result['extras']

    # Get AI analysis
    ai_text = get_free_ai_analysis(normalized, verdict, risk_score, extras)

    # Store in DB
    conn = get_db()
    c    = conn.cursor()
    c.execute("""
        INSERT INTO scans (url, url_hash, verdict, risk_score, ml_score, lr_score, features, ai_analysis, ip_address, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (
        normalized, url_hash, verdict, risk_score,
        result.get('ml_score'), result.get('lr_score'),
        json.dumps(result['features']),
        ai_text,
        request.remote_addr,
        datetime.utcnow().isoformat()
    ))
    c.execute("UPDATE stats SET value = value + 1 WHERE key = 'total_scans'")
    c.execute(f"UPDATE stats SET value = value + 1 WHERE key = '{verdict}_found'")
    conn.commit()
    conn.close()

    return jsonify({
        'url':        normalized,
        'verdict':    verdict,
        'risk_score': risk_score,
        'ml_score':   result.get('ml_score'),
        'lr_score':   result.get('lr_score'),
        'indicators': indicators,
        'ai_analysis': ai_text,
        'domain':     extras.get('domain'),
        'timestamp':  datetime.utcnow().isoformat(),
    })


@app.route('/api/bulk', methods=['POST'])
def api_bulk():
    body = request.get_json(silent=True) or {}
    urls = body.get('urls', [])
    if not urls or not isinstance(urls, list):
        return jsonify({'error': 'urls array required'}), 400
    urls = [str(u).strip() for u in urls[:30] if u]

    results = []
    conn = get_db()
    c = conn.cursor()
    for url in urls:
        normalized = url if url.startswith('http') else 'https://' + url
        url_hash   = hashlib.md5(normalized.encode()).hexdigest()
        result = ensemble_predict(normalized)
        verdict    = result['verdict']
        risk_score = result['risk_score']
        c.execute("""
            INSERT INTO scans (url, url_hash, verdict, risk_score, ml_score, lr_score, features, created_at)
            VALUES (?,?,?,?,?,?,?,?)
        """, (normalized, url_hash, verdict, risk_score,
              result.get('ml_score'), result.get('lr_score'),
              json.dumps(result['features']), datetime.utcnow().isoformat()))
        c.execute("UPDATE stats SET value = value + 1 WHERE key = 'total_scans'")
        c.execute(f"UPDATE stats SET value = value + 1 WHERE key = '{verdict}_found'")
        results.append({'url': normalized, 'verdict': verdict, 'risk_score': risk_score,
                        'ml_score': result.get('ml_score')})
    conn.commit()
    conn.close()
    return jsonify({'results': results, 'count': len(results)})


@app.route('/api/history', methods=['GET'])
def api_history():
    limit  = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))
    conn = get_db()
    rows = conn.execute("""
        SELECT id, url, verdict, risk_score, ml_score, lr_score, ai_analysis, created_at
        FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?
    """, (limit, offset)).fetchall()
    conn.close()
    return jsonify({'history': [dict(r) for r in rows], 'limit': limit, 'offset': offset})


@app.route('/api/stats', methods=['GET'])
def api_stats():
    conn = get_db()
    rows = conn.execute("SELECT key, value FROM stats").fetchall()
    stats_dict = {r['key']: r['value'] for r in rows}

    # Distribution
    dist = conn.execute("""
        SELECT verdict, COUNT(*) as cnt FROM scans GROUP BY verdict
    """).fetchall()
    stats_dict['distribution'] = {r['verdict']: r['cnt'] for r in dist}

    # Recent 24h
    recent = conn.execute("""
        SELECT COUNT(*) as cnt FROM scans
        WHERE created_at > datetime('now', '-24 hours')
    """).fetchone()
    stats_dict['last_24h'] = recent['cnt'] if recent else 0

    # Model info
    if WEIGHTS_DATA:
        stats_dict['lr_accuracy']  = WEIGHTS_DATA.get('accuracy')
        stats_dict['lr_f1']        = WEIGHTS_DATA.get('f1')
    if RF_MODEL:
        stats_dict['rf_accuracy']  = RF_MODEL.get('accuracy')
        stats_dict['rf_f1']        = RF_MODEL.get('f1')
    stats_dict.update(get_rf_state())
    conn.close()
    return jsonify(stats_dict)


@app.route('/api/search', methods=['GET'])
def api_search():
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify({'results': []})
    conn = get_db()
    rows = conn.execute("""
        SELECT id, url, verdict, risk_score, created_at FROM scans
        WHERE url LIKE ? ORDER BY created_at DESC LIMIT 20
    """, (f'%{q}%',)).fetchall()
    conn.close()
    return jsonify({'results': [dict(r) for r in rows]})


@app.route('/api/model-info', methods=['GET'])
def api_model_info():
    info = {
        'models': [],
        'feature_count': len(WEIGHTS_DATA['feature_names']) if WEIGHTS_DATA else 0,
        'features': WEIGHTS_DATA['feature_names'] if WEIGHTS_DATA else [],
        'dataset': 'detection_x_merged.csv (60,235 URLs)',
    }
    info.update(get_rf_state())
    if WEIGHTS_DATA:
        info['models'].append({'name': 'Logistic Regression', 'accuracy': WEIGHTS_DATA.get('accuracy'), 'f1': WEIGHTS_DATA.get('f1')})
    if RF_MODEL and RF_ENABLED:
        info['models'].append({'name': 'Random Forest (100 trees, max_depth=15)', 'accuracy': RF_MODEL.get('accuracy'), 'f1': RF_MODEL.get('f1')})
    if len(info['models']) > 1:
        info['ensemble'] = 'RF(60%) + LR(40%) weighted average'
    elif RF_MODEL and not RF_ENABLED:
        info['ensemble'] = 'LR-only mode (RF disabled by user)'
    return jsonify(info)


# ════════════════════════════════════════
#  SERVE FRONTEND
# ════════════════════════════════════════
@app.route('/')
def serve_index():
    return send_from_directory(str(FRONTEND), 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(str(FRONTEND), filename)


if __name__ == '__main__':
    print("\n" + "═"*55)
    print("  CyberSentinel Backend — Starting Up")
    print("═"*55)
    print(f"  DB:       {DB_PATH}")
    print(f"  Frontend: {FRONTEND}")
    print(f"  RF Model: {'✓ Loaded' if RF_MODEL else '✗ Not found'}")
    print(f"  RF Toggle:{'✓ Enabled' if (RF_MODEL and RF_ENABLED) else '✗ Disabled'}")
    print(f"  LR Weights:{'✓ Loaded' if WEIGHTS_DATA else '✗ Not found'}")
    print("  API: http://localhost:5000/api/")
    print("  App: http://localhost:5000/")
    print("═"*55 + "\n")
    app.run(debug=True, port=5000, host='0.0.0.0')
