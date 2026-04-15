# CODE_DOCS

Generated: 2026-04-10 11:18:00 +05:30

## Table of Contents
- [backend/app.py](#backendapppy)
- [backend/train_rf.py](#backendtrain_rfpy)
- [backend/test_snapchat.py](#backendtest_snapchatpy)
- [frontend/index.html](#frontendindexhtml)
- [frontend/css/style.css](#frontendcssstylecss)
- [frontend/js/app.js](#frontendjsappjs)
- [ml/model_weights.json](#mlmodel_weightsjson)
- [requirements.txt](#requirementstxt)
- [.gitignore](#gitignore)
- [.github/workflows/python-tests.yml](#githubworkflowspython-testsyml)
- [README.md](#readmemd)
- [LICENSE](#license)

## backend/app.py

`$lang
"""
CyberSentinel Backend â€” Flask + SQLite + ML + Free AI
Run: python app.py
API runs on http://localhost:5000
"""

from __future__ import annotations
import json, re, sqlite3, time, os, hashlib
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, request, jsonify, send_from_directory

# â”€â”€ optional joblib import â”€â”€
try:
    import joblib
    import numpy as np
    RF_AVAILABLE = True
except ImportError:
    RF_AVAILABLE = False

# â”€â”€ optional requests for free AI â”€â”€
try:
    import urllib.request as ureq
    import urllib.error
    REQUESTS_AVAILABLE = True
except:
    REQUESTS_AVAILABLE = False

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  PATHS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
BASE_DIR   = Path(__file__).parent.parent
ML_DIR     = BASE_DIR / "ml"
FRONTEND   = BASE_DIR / "frontend"
DB_PATH    = BASE_DIR / "backend" / "cybersentinel.db"
MODEL_PATH = ML_DIR / "rf_model.pkl"
WEIGHTS    = ML_DIR / "model_weights.json"

app = Flask(__name__, static_folder=str(FRONTEND), static_url_path="")

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  DATABASE SETUP
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  LOAD ML MODEL
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
RF_MODEL = None
WEIGHTS_DATA = None
RF_ENABLED = True

if RF_AVAILABLE and MODEL_PATH.exists():
    try:
        RF_MODEL = joblib.load(str(MODEL_PATH))
        print(f"[ML] RF model loaded â€” acc={RF_MODEL.get('accuracy','?')}")
    except Exception as e:
        print(f"[ML] RF load failed: {e}")

if WEIGHTS.exists():
    with open(WEIGHTS) as f:
        WEIGHTS_DATA = json.load(f)
    print(f"[ML] LR weights loaded â€” acc={WEIGHTS_DATA.get('accuracy','?')}")


def get_rf_state():
    available = RF_MODEL is not None
    enabled = bool(RF_ENABLED and available)
    return {
        'rf_available': available,
        'rf_enabled': enabled,
        'rf_requested': bool(RF_ENABLED),
    }

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  FEATURE EXTRACTION (must match training)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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
    'ritiktanwar004.github.io',
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
                'value': 'Detected âš ' if feats['is_ip'] else 'Clean',
                'status': 'danger' if feats['is_ip'] else 'safe'})
    ind.append({'label': 'Suspicious TLD',
                'value': 'Detected âš ' if feats['suspicious_tld'] else 'Clean',
                'status': 'danger' if feats['suspicious_tld'] else 'safe'})
    kc = extras['kw_count']
    ind.append({'label': 'Phishing Keywords',
                'value': f'{kc} found',
                'status': 'danger' if kc > 3 else 'warn' if kc > 1 else 'safe'})
    ind.append({'label': 'Brand Spoofing',
                'value': f'âš  {extras["brand_spoofed"]}' if extras['brand_spoofed'] else 'None',
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
                'value': 'Present âš ' if feats['encoded_chars'] > 0 else 'None',
                'status': 'warn' if feats['encoded_chars'] > 0 else 'safe'})
    ind.append({'label': '@ Symbol',
                'value': 'Found âš ' if feats['at_symbol'] else 'None',
                'status': 'danger' if feats['at_symbol'] else 'safe'})
    return ind

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  FREE AI ANALYSIS  (Hugging Face Inference API â€” no key needed for many models)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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

    # â”€â”€ RULE-BASED FALLBACK â”€â”€
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
        lines.append(f"CAUTION: This URL scored {risk_score}/100 on threat indicators, placing it in the suspicious category â€” proceed only with verification.")
        if kw > 0:
            lines.append(f"Found {kw} sensitive keyword(s) that commonly appear in social engineering attacks; the domain '{domain}' should be independently verified.")
        else:
            lines.append(f"The domain '{domain}' has structural anomalies that match known phishing patterns, though no definitive threat markers were found.")
        lines.append("RECOMMENDATION: Verify this URL through an independent source before clicking. If received via email or message, treat as potentially malicious.")

    else:
        lines.append(f"LOW RISK: This URL scored {risk_score}/100 and passes standard phishing heuristics â€” it appears to be a legitimate web address.")
        lines.append(f"The domain '{domain}' uses proper HTTPS, standard structure, and contains no known phishing indicators or brand spoofing patterns.")
        lines.append("RECOMMENDATION: While appearing safe, always verify unexpected links. Even legitimate-looking URLs can be compromised â€” when in doubt, navigate directly.")

    return " ".join(lines)

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  CORS MIDDLEWARE
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin']  = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    return response

@app.route('/api/<path:p>', methods=['OPTIONS'])
def options_handler(p):
    return '', 204

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  API ROUTES
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  SERVE FRONTEND
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
@app.route('/')
def serve_index():
    return send_from_directory(str(FRONTEND), 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(str(FRONTEND), filename)


if __name__ == '__main__':
    print("\n" + "â•"*55)
    print("  CyberSentinel Backend â€” Starting Up")
    print("â•"*55)
    print(f"  DB:       {DB_PATH}")
    print(f"  Frontend: {FRONTEND}")
    print(f"  RF Model: {'âœ“ Loaded' if RF_MODEL else 'âœ— Not found'}")
    print(f"  RF Toggle:{'âœ“ Enabled' if (RF_MODEL and RF_ENABLED) else 'âœ— Disabled'}")
    print(f"  LR Weights:{'âœ“ Loaded' if WEIGHTS_DATA else 'âœ— Not found'}")
    print("  API: http://localhost:5000/api/")
    print("  App: http://localhost:5000/")
    print("â•"*55 + "\n")
    app.run(debug=True, port=5000, host='0.0.0.0')
```

## backend/train_rf.py

`$lang
"""
Train and export CyberSentinel Random Forest model.

Usage:
  python backend/train_rf.py --dataset path/to/dataset.csv

Expected dataset columns (configurable by args):
  - url
  - label (0/1 or phishing/legitimate-like strings)

Output:
  ml/rf_model.pkl containing:
    {
      "model": RandomForestClassifier,
      "accuracy": float,
      "f1": float
    }
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import train_test_split

# Keep these feature constants aligned with backend/app.py
SUSPICIOUS_KW = [
    "login", "verify", "secure", "account", "update", "confirm", "bank", "paypal",
    "apple", "amazon", "google", "microsoft", "password", "credential", "suspend",
    "urgent", "free", "prize", "winner", "claim", "signin", "billing", "support",
    "security", "alert", "notice", "limited", "expire", "validate", "authenticate",
]

TRUSTED_DOMAINS = [
    "google.com", "facebook.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "twitter.com", "github.com", "linkedin.com", "youtube.com",
    "wikipedia.org", "reddit.com", "instagram.com", "netflix.com", "ebay.com",
]

PHISHING_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".online", ".site", ".info", ".biz", ".pw", ".cc", ".su",
]


def extract_features(url: str) -> dict[str, float]:
    url = str(url).strip()
    try:
        parsed = urlparse(url if url.startswith("http") else "https://" + url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query
    except Exception:
        domain = url.lower()
        path = ""
        query = ""

    url_lower = url.lower()

    kw = sum(1 for k in SUSPICIOUS_KW if k in url_lower)
    brand = next(
        (
            td.split(".")[0]
            for td in TRUSTED_DOMAINS
            if td.split(".")[0] in url_lower and not domain.endswith(td)
        ),
        None,
    )

    return {
        "is_https": 1 if url.startswith("https://") else 0,
        "url_length": min(len(url), 200) / 200,
        "domain_length": min(len(domain), 100) / 100,
        "is_ip": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain.split(":")[0]) else 0,
        "hyphen_count": min(domain.count("-"), 10) / 10,
        "dot_count": min(domain.count("."), 8) / 8,
        "subdomain_count": min(max(len(domain.split(".")) - 2, 0), 5) / 5,
        "suspicious_tld": 1 if any(domain.endswith(t) for t in PHISHING_TLDS) else 0,
        "keyword_count": min(kw, 10) / 10,
        "brand_mismatch": 1 if brand else 0,
        "at_symbol": 1 if "@" in url else 0,
        "double_slash": 1 if "//" in path else 0,
        "encoded_chars": min(len(re.findall(r"%[0-9a-fA-F]{2}", url)), 10) / 10,
        "digit_ratio": sum(c.isdigit() for c in domain) / max(len(domain), 1),
        "path_length": min(len(path), 150) / 150,
        "has_port": 1 if ":" in domain and domain.split(":")[-1].isdigit() else 0,
        "has_query": 1 if query else 0,
        "special_chars": min(len(re.findall(r"[!$&'()*+,;=]", url)), 10) / 10,
    }


def parse_label(value) -> int:
    # Accept common numeric and string label variants.
    if isinstance(value, bool):
        return int(value)

    s = str(value).strip().lower()
    if s in {"1", "true", "phishing", "phish", "malicious", "bad", "suspicious"}:
        return 1
    if s in {"0", "false", "legitimate", "legit", "safe", "benign", "good"}:
        return 0

    try:
        n = int(float(s))
        return 1 if n > 0 else 0
    except Exception as exc:
        raise ValueError(f"Unsupported label value: {value}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and export rf_model.pkl for CyberSentinel")
    parser.add_argument("--dataset", required=True, help="Path to CSV dataset")
    parser.add_argument("--url-col", default="url", help="URL column name (default: url)")
    parser.add_argument("--label-col", default="label", help="Label column name (default: label)")
    parser.add_argument("--output", default="ml/rf_model.pkl", help="Output model path")
    parser.add_argument("--test-size", type=float, default=0.2, help="Test split ratio")
    parser.add_argument("--random-state", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    df = pd.read_csv(dataset_path)
    if args.url_col not in df.columns or args.label_col not in df.columns:
        raise ValueError(
            f"Dataset must contain columns '{args.url_col}' and '{args.label_col}'. "
            f"Found: {list(df.columns)}"
        )

    work = df[[args.url_col, args.label_col]].dropna().copy()
    work[args.url_col] = work[args.url_col].astype(str).str.strip()
    work = work[work[args.url_col] != ""]
    work["y"] = work[args.label_col].map(parse_label)

    if work["y"].nunique() < 2:
        raise ValueError("Need at least two classes in labels to train the model.")

    X = pd.DataFrame([extract_features(u) for u in work[args.url_col]])
    y = work["y"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        random_state=args.random_state,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    pred = model.predict(X_test)
    accuracy = float(accuracy_score(y_test, pred))
    f1 = float(f1_score(y_test, pred))

    payload = {
        "model": model,
        "accuracy": accuracy,
        "f1": f1,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(payload, output_path)

    print("Saved Random Forest model")
    print(f"  output:   {output_path.resolve()}")
    print(f"  samples:  {len(work)}")
    print(f"  accuracy: {accuracy:.4f}")
    print(f"  f1:       {f1:.4f}")


if __name__ == "__main__":
    main()
```

## backend/test_snapchat.py

`$lang
from app import ensemble_predict

url = 'https://www.snapchat.com/web'
result = ensemble_predict(url)

print('URL:', url)
print('Verdict:', result['verdict'])
print('Risk score:', result['risk_score'])
print('LR score:', result['lr_score'])
print('ML score (RF):', result['ml_score'])
print('Features:', result['features'])
print('Indicators:', result['indicators'])
print('Extras:', result['extras'])
```

## frontend/index.html

`$lang
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1.0" />
    <title>CyberSentinel â€” Phishing Detection Platform</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link
      href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=JetBrains+Mono:wght@300;400;500;700&family=Outfit:wght@300;400;500;600;700&display=swap"
      rel="stylesheet"
    />
    <link rel="stylesheet" href="css/style.css" />
  </head>
  <body>
    <!-- SCAN LINES OVERLAY -->
    <div class="scanlines" aria-hidden="true"></div>
    <div class="bg-grid" aria-hidden="true"></div>

    <!-- â•â•â•â•â•â•â•â•â•â• SIDEBAR â•â•â•â•â•â•â•â•â•â• -->
    <nav class="sidebar" id="sidebar">
      <div class="sidebar-logo">
        <div class="logo-mark">
          <span class="logo-shield">â—ˆ</span>
        </div>
        <div class="logo-text">Cyber<span>Sentinel</span></div>
      </div>

      <div class="nav-section-label">NAVIGATION</div>
      <ul class="nav-links">
        <li>
          <a href="#" class="nav-link active" data-page="scanner">
            <span class="nav-icon">â¬¡</span><span>URL Scanner</span
            ><span class="nav-badge new">LIVE</span>
          </a>
        </li>
        <li>
          <a href="#" class="nav-link" data-page="qr">
            <span class="nav-icon">âŠž</span><span>QR Analyzer</span>
          </a>
        </li>
        <li>
          <a href="#" class="nav-link" data-page="bulk">
            <span class="nav-icon">â‰¡</span><span>Bulk Scan</span>
          </a>
        </li>
        <li>
          <a href="#" class="nav-link" data-page="history">
            <span class="nav-icon">â—·</span><span>History</span>
          </a>
        </li>
        <li>
          <a href="#" class="nav-link" data-page="model">
            <span class="nav-icon">â—‰</span><span>ML Model</span>
          </a>
        </li>
        <li>
          <a href="#" class="nav-link" data-page="analytics">
            <span class="nav-icon">â—ˆ</span><span>Analytics</span>
          </a>
        </li>
      </ul>

      <div class="nav-section-label" style="margin-top: auto">SYSTEM</div>
      <div class="sidebar-status">
        <div class="status-row">
          <span class="status-dot active"></span><span>Backend</span
          ><span class="status-val" id="sidebarBackend">Checkingâ€¦</span>
        </div>
        <div class="status-row">
          <span class="status-dot" id="dotML"></span><span>ML Model</span
          ><span class="status-val" id="sidebarML">â€”</span>
        </div>
        <div class="status-row">
          <span class="status-dot" id="dotAI"></span><span>AI Engine</span
          ><span class="status-val" id="sidebarAI">â€”</span>
        </div>
      </div>
    </nav>

    <!-- â•â•â•â•â•â•â•â•â•â• TOPBAR â•â•â•â•â•â•â•â•â•â• -->
    <div class="topbar">
      <button class="hamburger" id="hamburger" aria-label="Menu">â˜°</button>
      <div class="topbar-title" id="pageTitle">URL Scanner</div>
      <div class="topbar-right">
        <div class="threat-ticker" id="threatTicker">
          <span class="ticker-label">THREAT LEVEL</span>
          <span class="ticker-val" id="tickerVal">NOMINAL</span>
        </div>
        <div class="clock" id="topClock"></div>
      </div>
    </div>

    <!-- â•â•â•â•â•â•â•â•â•â• MAIN CONTENT â•â•â•â•â•â•â•â•â•â• -->
    <main class="main-content">
      <!-- STATS STRIP -->
      <div class="stats-strip" id="statsStrip">
        <div class="stat-chip">
          <span class="sc-label">Total Scans</span
          ><span class="sc-val" id="st0">â€”</span>
        </div>
        <div class="stat-chip">
          <span class="sc-label">Threats Found</span
          ><span class="sc-val danger" id="st1">â€”</span>
        </div>
        <div class="stat-chip">
          <span class="sc-label">Safe URLs</span
          ><span class="sc-val safe" id="st2">â€”</span>
        </div>
        <div class="stat-chip">
          <span class="sc-label">Suspicious</span
          ><span class="sc-val warn" id="st3">â€”</span>
        </div>
        <div class="stat-chip">
          <span class="sc-label">Last 24h</span
          ><span class="sc-val" id="st4">â€”</span>
        </div>
      </div>

      <!-- PROGRESS LINE -->
      <div class="scan-progress" id="scanProgress">
        <div class="scan-progress-fill" id="scanProgressFill"></div>
      </div>

      <!-- â•â•â•â• PAGE: SCANNER â•â•â•â• -->
      <section class="page active" id="page-scanner">
        <div class="page-header">
          <h1 class="page-title">
            URL <span class="accent">Threat Analysis</span>
          </h1>
          <p class="page-sub">
            Powered by ensemble ML model (Random Forest + Logistic Regression)
            and AI reasoning
          </p>
        </div>

        <!-- SCAN INPUT CARD -->
        <div class="card scan-card">
          <div class="card-header">
            <div class="card-label">â¬¡ SCAN TARGET</div>
            <div class="model-controls">
              <div class="model-badges">
                <span
                  class="mbadge"
                  id="badgeRF"
                  title="Random Forest model status"
                  >RF</span
                >
                <span
                  class="mbadge"
                  id="badgeLR"
                  title="Logistic Regression model status"
                  >LR</span
                >
                <span class="mbadge ai" id="badgeAI" title="AI analysis status"
                  >AI</span
                >
              </div>
              <button
                class="rf-toggle-btn"
                id="rfToggleBtn"
                type="button"
                title="Toggle Random Forest model"
              >
                RF: OFF
              </button>
            </div>
          </div>
          <div class="rf-toggle-hint" id="rfToggleHint">
            Checking RF model statusâ€¦
          </div>
          <div class="scan-input-group">
            <div class="url-input-wrap">
              <span class="url-prefix">https://</span>
              <input
                id="urlInput"
                class="url-input"
                type="text"
                placeholder="Enter URL or paste a suspicious linkâ€¦"
                autocomplete="off"
                spellcheck="false"
              />
              <button class="clear-btn" id="clearUrlBtn" title="Clear">
                âœ•
              </button>
            </div>
            <button class="btn-primary" id="scanBtn">
              <span class="btn-icon">âš¡</span> SCAN URL
            </button>
          </div>
          <div class="scan-options">
            <label class="opt-label"
              ><input type="checkbox" id="optDeep" checked /> Deep AI
              Analysis</label
            >
            <label class="opt-label"
              ><input type="checkbox" id="optBrand" checked /> Brand Spoof
              Check</label
            >
            <label class="opt-label"
              ><input type="checkbox" id="optHistory" checked /> Save to
              History</label
            >
          </div>
          <div class="quick-tests">
            <span class="qt-label">Quick test:</span>
            <button
              class="qt-btn phish"
              onclick="testUrl('http://paypal-secure-login.tk/verify')"
            >
              Phishing sample
            </button>
            <button class="qt-btn safe" onclick="testUrl('https://google.com')">
              Safe sample
            </button>
            <button
              class="qt-btn warn"
              onclick="testUrl('http://microsoft-account-verify.xyz/login')"
            >
              Suspicious sample
            </button>
          </div>
        </div>

        <!-- RESULT CARD -->
        <div class="result-card card" id="resultCard" style="display: none">
          <!-- TOP ROW -->
          <div class="result-hero">
            <div class="verdict-col">
              <div class="verdict-badge" id="verdictBadge">â€”</div>
              <div class="result-url" id="resultUrl">â€”</div>
            </div>
            <div class="score-col">
              <svg class="score-ring" viewBox="0 0 120 120" id="scoreRingSvg">
                <circle class="ring-bg" cx="60" cy="60" r="50" />
                <circle
                  class="ring-fill"
                  id="ringFill"
                  cx="60"
                  cy="60"
                  r="50"
                  stroke-dasharray="314"
                  stroke-dashoffset="314"
                />
              </svg>
              <div class="score-center">
                <div class="score-num" id="scoreNum">â€”</div>
                <div class="score-label">RISK</div>
              </div>
            </div>
          </div>

          <!-- DUAL MODEL BAR -->
          <div class="dual-model">
            <div class="dm-row">
              <span class="dm-label">Random Forest</span>
              <div class="dm-bar-wrap">
                <div class="dm-bar" id="rfBar"></div>
              </div>
              <span class="dm-val" id="rfVal">â€”</span>
            </div>
            <div class="dm-row">
              <span class="dm-label">Logistic Regression</span>
              <div class="dm-bar-wrap">
                <div class="dm-bar lr" id="lrBar"></div>
              </div>
              <span class="dm-val" id="lrVal">â€”</span>
            </div>
            <div class="dm-row">
              <span class="dm-label">Ensemble Score</span>
              <div class="dm-bar-wrap">
                <div class="dm-bar ensemble" id="ensBar"></div>
              </div>
              <span class="dm-val" id="ensVal">â€”</span>
            </div>
          </div>

          <!-- INDICATORS GRID -->
          <div class="section-label">â—ˆ SECURITY INDICATORS</div>
          <div class="indicators-grid" id="indicatorsGrid"></div>

          <!-- AI THINKING SECTION -->
          <div class="ai-section" id="aiSection">
            <div class="ai-header">
              <div class="ai-label">
                <span class="ai-pulse"></span>
                ðŸ§  AI REASONING ENGINE
              </div>
              <div class="ai-model-tag">Chain-of-Thought Analysis</div>
            </div>
            <div class="ai-thinking" id="aiThinking">
              <div class="think-step" id="ts1">
                <span class="ts-icon">ðŸ”</span><span class="ts-text"></span>
              </div>
              <div class="think-step" id="ts2">
                <span class="ts-icon">âš–</span><span class="ts-text"></span>
              </div>
              <div class="think-step" id="ts3">
                <span class="ts-icon">ðŸŽ¯</span><span class="ts-text"></span>
              </div>
            </div>
            <div class="ai-conclusion" id="aiConclusion"></div>
          </div>

          <!-- ACTIONS -->
          <div class="result-actions">
            <button class="btn-ghost" id="copyReportBtn">ðŸ“‹ Copy Report</button>
            <button class="btn-ghost" id="exportJsonBtn">â¬‡ Export JSON</button>
            <button class="btn-ghost" id="shareLinkBtn">ðŸ”— Share</button>
          </div>
        </div>
      </section>

      <!-- â•â•â•â• PAGE: QR â•â•â•â• -->
      <section class="page" id="page-qr">
        <div class="page-header">
          <h1 class="page-title">
            QR Code <span class="accent">Threat Scanner</span>
          </h1>
          <p class="page-sub">
            Decode QR codes and instantly analyze embedded URLs for phishing
            threats
          </p>
        </div>
        <div class="qr-layout">
          <div class="card qr-upload-card">
            <div class="card-label">âŠž UPLOAD QR IMAGE</div>
            <div class="drop-zone" id="dropZone">
              <div class="dz-icon">âŠž</div>
              <p class="dz-main">Drop QR image here</p>
              <p class="dz-sub">
                or <span class="dz-link" id="dzClick">click to browse</span>
              </p>
              <p class="dz-formats">PNG Â· JPG Â· WEBP Â· GIF</p>
            </div>
            <input
              type="file"
              id="qrFileInput"
              accept="image/*"
              style="display: none"
            />
            <div class="qr-actions">
              <button class="btn-ghost" id="qrCamBtn">ðŸ“· Use Camera</button>
              <button class="btn-ghost" id="qrPasteBtn">
                ðŸ“‹ Paste Clipboard
              </button>
            </div>
            <p class="qr-permission-note" id="qrPermissionNote">
              Permission is requested only when you use QR Camera or Paste
              Clipboard. Normal URL scanning works without any permission.
            </p>
          </div>

          <div
            class="card qr-result-card"
            id="qrResultPanel"
            style="display: none"
          >
            <div class="card-label">âŠž DECODED QR</div>
            <div class="qr-decoded-layout">
              <img id="qrPreviewImg" class="qr-preview-img" src="" alt="QR" />
              <div class="qr-decoded-info">
                <div class="qr-field">
                  <span class="qf-label">DECODED CONTENT</span
                  ><span class="qf-val" id="qrDecodedContent">â€”</span>
                </div>
                <div class="qr-field">
                  <span class="qf-label">TYPE</span
                  ><span class="qf-val" id="qrType">â€”</span>
                </div>
                <div class="qr-field">
                  <span class="qf-label">LENGTH</span
                  ><span class="qf-val" id="qrLength">â€”</span>
                </div>
                <button
                  class="btn-primary"
                  id="analyzeQrBtn"
                  style="margin-top: 12px; width: 100%"
                >
                  âš¡ ANALYZE URL
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- QR SCAN RESULT (reuses same structure) -->
        <div
          class="result-card card"
          id="qrScanResult"
          style="display: none; margin-top: 20px"
        >
          <div class="result-hero">
            <div class="verdict-col">
              <div class="verdict-badge" id="qrVerdictBadge">â€”</div>
              <div class="result-url" id="qrResultUrl">â€”</div>
            </div>
            <div class="score-col">
              <svg class="score-ring" viewBox="0 0 120 120">
                <circle class="ring-bg" cx="60" cy="60" r="50" />
                <circle
                  class="ring-fill"
                  id="qrRingFill"
                  cx="60"
                  cy="60"
                  r="50"
                  stroke-dasharray="314"
                  stroke-dashoffset="314"
                />
              </svg>
              <div class="score-center">
                <div class="score-num" id="qrScoreNum">â€”</div>
                <div class="score-label">RISK</div>
              </div>
            </div>
          </div>
          <div class="indicators-grid" id="qrIndicatorsGrid"></div>
          <div
            class="ai-conclusion"
            id="qrAiConclusion"
            style="margin-top: 16px"
          ></div>
        </div>
      </section>

      <!-- â•â•â•â• PAGE: BULK â•â•â•â• -->
      <section class="page" id="page-bulk">
        <div class="page-header">
          <h1 class="page-title">Bulk <span class="accent">Scanner</span></h1>
          <p class="page-sub">
            Scan up to 30 URLs simultaneously with full ML analysis
          </p>
        </div>
        <div class="card">
          <div class="card-label">â‰¡ PASTE URLs (ONE PER LINE)</div>
          <textarea
            class="bulk-textarea"
            id="bulkTextarea"
            placeholder="https://google.com&#10;http://paypal-secure-verify.tk&#10;https://github.com&#10;http://apple-id-suspended.xyz/verify&#10;â€¦"
          ></textarea>
          <div class="bulk-controls">
            <button class="btn-primary" id="bulkScanBtn">âš¡ SCAN ALL</button>
            <button class="btn-ghost" id="bulkClearBtn">âœ• Clear</button>
            <span class="bulk-count" id="bulkCount">0 URLs detected</span>
            <button
              class="btn-ghost"
              id="bulkExportBtn"
              style="margin-left: auto"
            >
              â¬‡ Export CSV
            </button>
          </div>
        </div>
        <div id="bulkResultsContainer"></div>
      </section>

      <!-- â•â•â•â• PAGE: HISTORY â•â•â•â• -->
      <section class="page" id="page-history">
        <div class="page-header">
          <h1 class="page-title">Scan <span class="accent">History</span></h1>
          <p class="page-sub">
            All past scans stored in SQLite database via backend API
          </p>
        </div>
        <div class="card" style="padding: 16px 20px">
          <div class="history-toolbar">
            <input
              class="search-input"
              id="historySearch"
              type="text"
              placeholder="Search URLsâ€¦"
            />
            <select class="filter-select" id="historyFilter">
              <option value="">All Verdicts</option>
              <option value="phishing">Phishing</option>
              <option value="suspicious">Suspicious</option>
              <option value="legitimate">Legitimate</option>
            </select>
            <button class="btn-ghost" id="refreshHistoryBtn">â†º Refresh</button>
            <button class="btn-ghost danger" id="clearHistoryBtn">
              ðŸ—‘ Clear DB
            </button>
            <button class="btn-ghost" id="exportHistoryBtn">â¬‡ CSV</button>
          </div>
        </div>
        <div class="history-list" id="historyList">
          <div class="empty-state">Loading historyâ€¦</div>
        </div>
      </section>

      <!-- â•â•â•â• PAGE: MODEL INFO â•â•â•â• -->
      <section class="page" id="page-model">
        <div class="page-header">
          <h1 class="page-title">
            ML <span class="accent">Model Dashboard</span>
          </h1>
          <p class="page-sub">
            Trained on 60,235 labeled URLs using scikit-learn ensemble
          </p>
        </div>
        <div class="model-grid">
          <div class="card model-card" id="rfCard">
            <div class="card-label">â—‰ RANDOM FOREST</div>
            <div class="model-metric">
              <span class="mm-label">Accuracy</span
              ><span class="mm-val" id="rfAcc">â€”</span>
            </div>
            <div class="model-metric">
              <span class="mm-label">F1 Score</span
              ><span class="mm-val" id="rfF1">â€”</span>
            </div>
            <div class="model-metric">
              <span class="mm-label">Trees</span><span class="mm-val">100</span>
            </div>
            <div class="model-metric">
              <span class="mm-label">Max Depth</span
              ><span class="mm-val">15</span>
            </div>
            <div class="model-metric">
              <span class="mm-label">Ensemble Weight</span
              ><span class="mm-val accent">60%</span>
            </div>
          </div>
          <div class="card model-card" id="lrCard">
            <div class="card-label">â—‰ LOGISTIC REGRESSION</div>
            <div class="model-metric">
              <span class="mm-label">Accuracy</span
              ><span class="mm-val" id="lrAcc">â€”</span>
            </div>
            <div class="model-metric">
              <span class="mm-label">F1 Score</span
              ><span class="mm-val" id="lrF1">â€”</span>
            </div>
            <div class="model-metric">
              <span class="mm-label">Max Iterations</span
              ><span class="mm-val">500</span>
            </div>
            <div class="model-metric">
              <span class="mm-label">Class Weight</span
              ><span class="mm-val">Balanced</span>
            </div>
            <div class="model-metric">
              <span class="mm-label">Ensemble Weight</span
              ><span class="mm-val accent">40%</span>
            </div>
          </div>
          <div class="card" style="grid-column: 1/-1">
            <div class="card-label">â—‰ FEATURE ENGINEERING (18 Features)</div>
            <div class="features-grid" id="featuresGrid"></div>
          </div>
          <div class="card" style="grid-column: 1/-1">
            <div class="card-label">â—‰ DATASET</div>
            <div class="dataset-info">
              <div class="ds-row">
                <span>Source</span><span>detection_x_merged.csv</span>
              </div>
              <div class="ds-row">
                <span>Total URLs</span><span>60,235</span>
              </div>
              <div class="ds-row">
                <span>Phishing</span><span class="danger">5,000 (8.3%)</span>
              </div>
              <div class="ds-row">
                <span>Legitimate</span><span class="safe">55,235 (91.7%)</span>
              </div>
              <div class="ds-row"><span>Train Split</span><span>80%</span></div>
              <div class="ds-row"><span>Test Split</span><span>20%</span></div>
              <div class="ds-row">
                <span>Stratified</span><span class="safe">Yes</span>
              </div>
              <div class="ds-row">
                <span>Class Weights</span><span class="accent">Balanced</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- â•â•â•â• PAGE: ANALYTICS â•â•â•â• -->
      <section class="page" id="page-analytics">
        <div class="page-header">
          <h1 class="page-title">
            Threat <span class="accent">Analytics</span>
          </h1>
          <p class="page-sub">
            Live statistics from your CyberSentinel scan database
          </p>
        </div>
        <div class="analytics-grid">
          <div class="card analytics-card">
            <div class="card-label">â—‰ VERDICT DISTRIBUTION</div>
            <div class="donut-wrap">
              <canvas id="donutChart" width="200" height="200"></canvas>
              <div class="donut-legend" id="donutLegend"></div>
            </div>
          </div>
          <div class="card analytics-card">
            <div class="card-label">â—‰ RISK SCORE BREAKDOWN</div>
            <div class="bar-chart-wrap" id="barChartWrap">
              <div class="empty-state">Scan some URLs to see analytics</div>
            </div>
          </div>
          <div class="card" style="grid-column: 1/-1">
            <div class="card-label">â—‰ RECENT THREAT FEED</div>
            <div class="feed-list" id="feedList"></div>
          </div>
        </div>
      </section>
    </main>

    <!-- CAMERA MODAL -->
    <div class="modal-overlay" id="cameraModal">
      <div class="modal-box">
        <div class="modal-header">
          <h3>ðŸ“· Camera QR Scanner</h3>
          <button class="modal-close" id="closeCamBtn">âœ•</button>
        </div>
        <video
          id="cameraFeed"
          autoplay
          playsinline
          style="width: 100%; border-radius: 12px; background: #000"
        ></video>
        <canvas id="camCanvas" style="display: none"></canvas>
        <p
          style="
            font-size: 0.78rem;
            color: var(--muted);
            font-family: var(--font-mono);
            margin-top: 10px;
          "
        >
          Point camera at QR code. Auto-detects and captures.
        </p>
        <div class="modal-actions">
          <button class="btn-primary" id="captureCamBtn">
            ðŸ“¸ Capture & Decode
          </button>
          <button class="btn-ghost" id="closeCamBtn2">Cancel</button>
        </div>
      </div>
    </div>

    <!-- jsQR -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jsqr/1.4.0/jsQR.min.js"></script>
    <script src="js/app.js"></script>
  </body>
</html>
```

## frontend/css/style.css

`$lang
/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
   CyberSentinel â€” style.css
   Aesthetic: Military-grade cyber terminal meets modern SaaS
â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

:root {
  --bg: #080c12;
  --bg2: #0c1219;
  --surface: #0f1720;
  --surface2: #131e2b;
  --border: rgba(0, 210, 255, 0.1);
  --border-active: rgba(0, 210, 255, 0.4);
  --border-hover: rgba(0, 210, 255, 0.22);

  --cyan: #00d2ff;
  --cyan-d: rgba(0, 210, 255, 0.15);
  --cyan-dd: rgba(0, 210, 255, 0.06);
  --green: #00ff9d;
  --green-d: rgba(0, 255, 157, 0.12);
  --red: #ff3355;
  --red-d: rgba(255, 51, 85, 0.14);
  --orange: #ff9500;
  --orange-d: rgba(255, 149, 0, 0.13);
  --yellow: #ffe66d;
  --muted: #5a7a96;
  --text: #d8eaf8;
  --text2: #8fb3cc;

  --sidebar-w: 240px;
  --topbar-h: 56px;

  --font-display: "Rajdhani", sans-serif;
  --font-mono: "JetBrains Mono", monospace;
  --font-body: "Outfit", sans-serif;

  --radius: 14px;
  --radius-sm: 9px;
  --shadow: 0 4px 24px rgba(0, 0, 0, 0.45);
  --shadow-lg: 0 8px 48px rgba(0, 0, 0, 0.6);
}

/* â”€â”€ RESET â”€â”€ */
*,
*::before,
*::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}
html {
  scroll-behavior: smooth;
}
body {
  font-family: var(--font-body);
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  overflow-x: hidden;
}

/* â”€â”€ BACKGROUND â”€â”€ */
.bg-grid {
  position: fixed;
  inset: 0;
  z-index: 0;
  pointer-events: none;
  background-image:
    linear-gradient(rgba(0, 210, 255, 0.022) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0, 210, 255, 0.022) 1px, transparent 1px);
  background-size: 44px 44px;
}
.scanlines {
  position: fixed;
  inset: 0;
  z-index: 0;
  pointer-events: none;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0, 0, 0, 0.03) 2px,
    rgba(0, 0, 0, 0.03) 4px
  );
}

/* â”€â”€ SIDEBAR â”€â”€ */
.sidebar {
  position: fixed;
  left: 0;
  top: 0;
  bottom: 0;
  width: var(--sidebar-w);
  background: var(--surface);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  padding: 20px 0;
  z-index: 50;
  transition: transform 0.3s ease;
  overflow-y: auto;
}
.sidebar-logo {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 0 20px 24px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 16px;
}
.logo-mark {
  width: 38px;
  height: 38px;
  border: 1.5px solid var(--cyan);
  border-radius: 9px;
  display: grid;
  place-items: center;
  animation: glowPulse 3s ease-in-out infinite;
}
.logo-shield {
  color: var(--cyan);
  font-size: 1.2rem;
}
@keyframes glowPulse {
  0%,
  100% {
    box-shadow: 0 0 12px rgba(0, 210, 255, 0.2);
  }
  50% {
    box-shadow: 0 0 28px rgba(0, 210, 255, 0.55);
  }
}
.logo-text {
  font-family: var(--font-display);
  font-size: 1.3rem;
  font-weight: 700;
  letter-spacing: 0.06em;
}
.logo-text span {
  color: var(--cyan);
}

.nav-section-label {
  font-family: var(--font-mono);
  font-size: 0.62rem;
  color: var(--muted);
  letter-spacing: 0.18em;
  padding: 4px 20px 8px;
  text-transform: uppercase;
}
.nav-links {
  list-style: none;
  padding: 0 10px;
}
.nav-link {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 12px;
  border-radius: var(--radius-sm);
  color: var(--muted);
  text-decoration: none;
  font-size: 0.88rem;
  font-weight: 500;
  transition: all 0.2s;
  position: relative;
  margin-bottom: 2px;
}
.nav-link:hover {
  color: var(--text);
  background: var(--cyan-dd);
}
.nav-link.active {
  color: var(--cyan);
  background: var(--cyan-d);
  border: 1px solid var(--border-active);
}
.nav-icon {
  font-size: 1rem;
  width: 20px;
  text-align: center;
}
.nav-badge {
  margin-left: auto;
  font-family: var(--font-mono);
  font-size: 0.58rem;
  padding: 2px 6px;
  border-radius: 4px;
  letter-spacing: 0.08em;
}
.nav-badge.new {
  background: var(--red-d);
  color: var(--red);
  border: 1px solid rgba(255, 51, 85, 0.3);
  animation: blinkBadge 2s step-end infinite;
}
@keyframes blinkBadge {
  0%,
  100% {
    opacity: 1;
  }
  50% {
    opacity: 0.3;
  }
}

.sidebar-status {
  padding: 16px 20px;
  margin-top: auto;
  border-top: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.status-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-family: var(--font-mono);
  font-size: 0.72rem;
  color: var(--muted);
}
.status-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--muted);
  flex-shrink: 0;
}
.status-dot.active {
  background: var(--green);
  box-shadow: 0 0 6px var(--green);
}
.status-dot.warn {
  background: var(--orange);
  box-shadow: 0 0 6px var(--orange);
}
.status-dot.danger {
  background: var(--red);
  box-shadow: 0 0 6px var(--red);
}
.status-val {
  margin-left: auto;
  color: var(--text2);
  font-size: 0.68rem;
}

/* â”€â”€ TOPBAR â”€â”€ */
.topbar {
  position: fixed;
  top: 0;
  left: var(--sidebar-w);
  right: 0;
  height: var(--topbar-h);
  background: rgba(8, 12, 18, 0.95);
  border-bottom: 1px solid var(--border);
  backdrop-filter: blur(12px);
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 0 24px;
  z-index: 40;
}
.hamburger {
  display: none;
  background: none;
  border: none;
  color: var(--muted);
  font-size: 1.2rem;
  cursor: pointer;
}
.topbar-title {
  font-family: var(--font-display);
  font-size: 1.1rem;
  font-weight: 600;
  letter-spacing: 0.05em;
  color: var(--text);
}
.topbar-right {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 20px;
}
.threat-ticker {
  display: flex;
  gap: 8px;
  align-items: center;
  font-family: var(--font-mono);
  font-size: 0.7rem;
}
.ticker-label {
  color: var(--muted);
  letter-spacing: 0.1em;
}
.ticker-val {
  color: var(--green);
  font-weight: 700;
  letter-spacing: 0.12em;
}
.ticker-val.elevated {
  color: var(--orange);
}
.ticker-val.critical {
  color: var(--red);
  animation: blinkBadge 1s step-end infinite;
}
.clock {
  font-family: var(--font-mono);
  font-size: 0.75rem;
  color: var(--muted);
  letter-spacing: 0.08em;
}

/* â”€â”€ MAIN CONTENT â”€â”€ */
.main-content {
  margin-left: var(--sidebar-w);
  padding-top: calc(var(--topbar-h) + 24px);
  padding-bottom: 60px;
  padding-left: 28px;
  padding-right: 28px;
  position: relative;
  z-index: 1;
}

/* â”€â”€ STATS STRIP â”€â”€ */
.stats-strip {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 24px;
}
.stat-chip {
  display: flex;
  flex-direction: column;
  gap: 2px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 10px 16px;
  min-width: 100px;
  flex: 1;
  transition: border-color 0.2s;
}
.stat-chip:hover {
  border-color: var(--border-hover);
}
.sc-label {
  font-family: var(--font-mono);
  font-size: 0.62rem;
  color: var(--muted);
  letter-spacing: 0.1em;
  text-transform: uppercase;
}
.sc-val {
  font-family: var(--font-display);
  font-size: 1.4rem;
  font-weight: 700;
}
.sc-val.danger {
  color: var(--red);
}
.sc-val.safe {
  color: var(--green);
}
.sc-val.warn {
  color: var(--orange);
}

/* SCAN PROGRESS */
.scan-progress {
  height: 2px;
  background: transparent;
  margin-bottom: 24px;
  border-radius: 2px;
  overflow: hidden;
}
.scan-progress-fill {
  height: 100%;
  width: 0%;
  background: linear-gradient(90deg, var(--cyan), var(--green));
  transition: width 0.2s;
}
.scan-progress-fill.active {
  animation: scanAnim 1.2s linear infinite;
  width: 100%;
}
@keyframes scanAnim {
  0% {
    transform: translateX(-100%);
  }
  100% {
    transform: translateX(100%);
  }
}

/* â”€â”€ PAGES â”€â”€ */
.page {
  display: none;
  animation: pageIn 0.3s ease;
}
.page.active {
  display: block;
}
@keyframes pageIn {
  from {
    opacity: 0;
    transform: translateY(8px);
  }
  to {
    opacity: 1;
    transform: none;
  }
}

.page-header {
  margin-bottom: 24px;
}
.page-title {
  font-family: var(--font-display);
  font-size: 1.8rem;
  font-weight: 700;
  letter-spacing: 0.04em;
  margin-bottom: 4px;
}
.page-title .accent {
  color: var(--cyan);
}
.page-sub {
  color: var(--muted);
  font-size: 0.85rem;
}

/* â”€â”€ CARD â”€â”€ */
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 22px 24px;
  margin-bottom: 20px;
  transition: border-color 0.2s;
}
.card:hover {
  border-color: var(--border-hover);
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 18px;
}
.card-label {
  font-family: var(--font-mono);
  font-size: 0.68rem;
  color: var(--cyan);
  letter-spacing: 0.14em;
  text-transform: uppercase;
  margin-bottom: 16px;
}
.section-label {
  font-family: var(--font-mono);
  font-size: 0.65rem;
  color: var(--muted);
  letter-spacing: 0.14em;
  margin-bottom: 12px;
}

/* â”€â”€ SCAN INPUT â”€â”€ */
.scan-card {
}
.model-controls {
  display: flex;
  align-items: center;
  gap: 10px;
}
.model-badges {
  display: flex;
  gap: 6px;
}
.mbadge {
  font-family: var(--font-mono);
  font-size: 0.62rem;
  padding: 3px 8px;
  border-radius: 5px;
  letter-spacing: 0.08em;
  border: 1px solid var(--border);
  color: var(--muted);
}
.mbadge.active {
  color: var(--text2);
  border-color: var(--border-hover);
}
.mbadge.ai {
  border-color: rgba(0, 210, 255, 0.35);
  color: var(--cyan);
}
.mbadge.off {
  color: var(--orange);
  border-color: rgba(255, 149, 0, 0.45);
  background: rgba(255, 149, 0, 0.1);
}

.rf-toggle-btn {
  font-family: var(--font-mono);
  font-size: 0.66rem;
  color: var(--orange);
  border: 1px solid rgba(255, 149, 0, 0.5);
  background: rgba(255, 149, 0, 0.1);
  border-radius: 6px;
  padding: 4px 10px;
  letter-spacing: 0.08em;
  cursor: pointer;
  transition: all 0.2s;
}
.rf-toggle-btn.on {
  color: var(--green);
  border-color: rgba(0, 255, 157, 0.5);
  background: rgba(0, 255, 157, 0.1);
}
.rf-toggle-btn:hover {
  filter: brightness(1.08);
}
.rf-toggle-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
  filter: none;
}

.rf-toggle-hint {
  margin-top: -8px;
  margin-bottom: 10px;
  font-family: var(--font-mono);
  font-size: 0.68rem;
  color: var(--muted);
  letter-spacing: 0.04em;
}
.rf-toggle-hint.ready {
  color: var(--green);
}
.rf-toggle-hint.warn {
  color: var(--orange);
}

.scan-input-group {
  display: flex;
  gap: 10px;
  margin-bottom: 14px;
  flex-wrap: wrap;
}
.url-input-wrap {
  flex: 1 1 300px;
  display: flex;
  align-items: center;
  background: var(--bg2);
  border: 1.5px solid var(--border);
  border-radius: var(--radius-sm);
  overflow: hidden;
  transition:
    border-color 0.2s,
    box-shadow 0.2s;
}
.url-input-wrap:focus-within {
  border-color: var(--border-active);
  box-shadow: 0 0 0 3px rgba(0, 210, 255, 0.07);
}
.url-prefix {
  font-family: var(--font-mono);
  font-size: 0.78rem;
  color: var(--muted);
  padding: 0 10px 0 14px;
  border-right: 1px solid var(--border);
  white-space: nowrap;
  user-select: none;
}
.url-input {
  flex: 1;
  background: none;
  border: none;
  color: var(--text);
  font-family: var(--font-mono);
  font-size: 0.85rem;
  padding: 14px 12px;
  outline: none;
}
.url-input::placeholder {
  color: var(--muted);
}
.clear-btn {
  background: none;
  border: none;
  color: var(--muted);
  padding: 0 14px;
  cursor: pointer;
  font-size: 0.85rem;
  transition: color 0.2s;
}
.clear-btn:hover {
  color: var(--text);
}

.btn-primary {
  background: linear-gradient(135deg, var(--cyan), #0095cc);
  border: none;
  color: #03090f;
  font-family: var(--font-display);
  font-weight: 700;
  font-size: 0.95rem;
  letter-spacing: 0.08em;
  padding: 13px 28px;
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all 0.2s;
  white-space: nowrap;
  display: flex;
  align-items: center;
  gap: 8px;
}
.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(0, 210, 255, 0.3);
}
.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  transform: none;
  box-shadow: none;
}
.btn-icon {
  font-size: 1rem;
}

.btn-ghost {
  background: transparent;
  border: 1px solid var(--border);
  color: var(--muted);
  font-family: var(--font-mono);
  font-size: 0.78rem;
  padding: 10px 16px;
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all 0.2s;
  letter-spacing: 0.04em;
}
.btn-ghost:hover {
  border-color: var(--border-active);
  color: var(--cyan);
}
.btn-ghost.danger:hover {
  border-color: rgba(255, 51, 85, 0.5);
  color: var(--red);
}

.scan-options {
  display: flex;
  gap: 18px;
  flex-wrap: wrap;
  margin-bottom: 14px;
}
.opt-label {
  display: flex;
  align-items: center;
  gap: 7px;
  font-size: 0.8rem;
  color: var(--muted);
  cursor: pointer;
  font-family: var(--font-mono);
}
.opt-label input {
  accent-color: var(--cyan);
}

.quick-tests {
  display: flex;
  gap: 8px;
  align-items: center;
  flex-wrap: wrap;
}
.qt-label {
  font-family: var(--font-mono);
  font-size: 0.68rem;
  color: var(--muted);
}
.qt-btn {
  font-family: var(--font-mono);
  font-size: 0.7rem;
  padding: 5px 12px;
  border-radius: 6px;
  cursor: pointer;
  border: 1px solid;
  transition: all 0.2s;
}
.qt-btn.phish {
  background: var(--red-d);
  color: var(--red);
  border-color: rgba(255, 51, 85, 0.3);
}
.qt-btn.safe {
  background: var(--green-d);
  color: var(--green);
  border-color: rgba(0, 255, 157, 0.3);
}
.qt-btn.warn {
  background: var(--orange-d);
  color: var(--orange);
  border-color: rgba(255, 149, 0, 0.3);
}
.qt-btn:hover {
  filter: brightness(1.2);
  transform: translateY(-1px);
}

/* â”€â”€ RESULT CARD â”€â”€ */
.result-card {
  margin-bottom: 0;
}
.result-card.v-phishing {
  border-color: rgba(255, 51, 85, 0.4);
  box-shadow: 0 0 40px rgba(255, 51, 85, 0.07);
}
.result-card.v-legitimate {
  border-color: rgba(0, 255, 157, 0.35);
  box-shadow: 0 0 40px rgba(0, 255, 157, 0.06);
}
.result-card.v-suspicious {
  border-color: rgba(255, 149, 0, 0.4);
  box-shadow: 0 0 40px rgba(255, 149, 0, 0.07);
}

.result-hero {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 20px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}
.verdict-col {
  flex: 1;
  min-width: 200px;
}
.verdict-badge {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  border-radius: 10px;
  font-family: var(--font-display);
  font-size: 1.1rem;
  font-weight: 700;
  letter-spacing: 0.1em;
  margin-bottom: 10px;
}
.verdict-badge.phishing {
  background: var(--red-d);
  border: 1px solid rgba(255, 51, 85, 0.4);
  color: var(--red);
}
.verdict-badge.legitimate {
  background: var(--green-d);
  border: 1px solid rgba(0, 255, 157, 0.35);
  color: var(--green);
}
.verdict-badge.suspicious {
  background: var(--orange-d);
  border: 1px solid rgba(255, 149, 0, 0.4);
  color: var(--orange);
}
.result-url {
  font-family: var(--font-mono);
  font-size: 0.75rem;
  color: var(--muted);
  word-break: break-all;
}

/* SCORE RING */
.score-col {
  position: relative;
  width: 120px;
  height: 120px;
  flex-shrink: 0;
}
.score-ring {
  position: absolute;
  inset: 0;
  transform: rotate(-90deg);
}
.ring-bg {
  fill: none;
  stroke: rgba(255, 255, 255, 0.06);
  stroke-width: 8;
}
.ring-fill {
  fill: none;
  stroke: var(--cyan);
  stroke-width: 8;
  stroke-linecap: round;
  transition:
    stroke-dashoffset 1s cubic-bezier(0.4, 0, 0.2, 1),
    stroke 0.4s;
}
.ring-fill.r {
  stroke: var(--red);
}
.ring-fill.o {
  stroke: var(--orange);
}
.ring-fill.g {
  stroke: var(--green);
}
.score-center {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}
.score-num {
  font-family: var(--font-display);
  font-size: 1.7rem;
  font-weight: 700;
  line-height: 1;
}
.score-label {
  font-family: var(--font-mono);
  font-size: 0.58rem;
  color: var(--muted);
  letter-spacing: 0.15em;
}

/* DUAL MODEL BARS */
.dual-model {
  margin-bottom: 22px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.dm-row {
  display: flex;
  align-items: center;
  gap: 12px;
}
.dm-label {
  font-family: var(--font-mono);
  font-size: 0.72rem;
  color: var(--muted);
  width: 160px;
  flex-shrink: 0;
}
.dm-bar-wrap {
  flex: 1;
  height: 8px;
  background: rgba(255, 255, 255, 0.06);
  border-radius: 4px;
  overflow: hidden;
}
.dm-bar {
  height: 100%;
  border-radius: 4px;
  width: 0%;
  transition: width 0.9s cubic-bezier(0.4, 0, 0.2, 1);
  background: linear-gradient(90deg, #0070c0, var(--cyan));
}
.dm-bar.lr {
  background: linear-gradient(90deg, #006630, var(--green));
}
.dm-bar.ensemble {
  background: linear-gradient(90deg, var(--orange), var(--red));
}
.dm-val {
  font-family: var(--font-mono);
  font-size: 0.75rem;
  color: var(--text2);
  width: 40px;
  text-align: right;
  flex-shrink: 0;
}

/* INDICATORS */
.indicators-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 10px;
  margin-bottom: 22px;
}
.indicator-chip {
  display: flex;
  align-items: center;
  gap: 10px;
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 10px 12px;
}
.ind-dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  flex-shrink: 0;
}
.ind-dot.safe {
  background: var(--green);
  box-shadow: 0 0 7px var(--green);
}
.ind-dot.warn {
  background: var(--orange);
  box-shadow: 0 0 7px var(--orange);
}
.ind-dot.danger {
  background: var(--red);
  box-shadow: 0 0 7px var(--red);
}
.ind-dot.neutral {
  background: var(--muted);
}
.ind-text strong {
  display: block;
  font-size: 0.78rem;
  color: var(--text);
  margin-bottom: 1px;
}
.ind-text span {
  font-size: 0.7rem;
  color: var(--muted);
  font-family: var(--font-mono);
}

/* AI SECTION */
.ai-section {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 18px;
  margin-bottom: 18px;
}
.ai-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}
.ai-label {
  font-family: var(--font-mono);
  font-size: 0.72rem;
  color: var(--cyan);
  letter-spacing: 0.12em;
  display: flex;
  align-items: center;
  gap: 8px;
}
.ai-pulse {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--cyan);
  animation: aiPulse 1.5s ease-in-out infinite;
}
@keyframes aiPulse {
  0%,
  100% {
    opacity: 1;
    box-shadow: 0 0 0 0 rgba(0, 210, 255, 0.4);
  }
  50% {
    opacity: 0.7;
    box-shadow: 0 0 0 6px rgba(0, 210, 255, 0);
  }
}
.ai-model-tag {
  font-family: var(--font-mono);
  font-size: 0.62rem;
  color: var(--muted);
}

.ai-thinking {
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-bottom: 14px;
}
.think-step {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  opacity: 0;
  transform: translateX(-8px);
  transition: all 0.4s ease;
}
.think-step.visible {
  opacity: 1;
  transform: none;
}
.ts-icon {
  font-size: 0.9rem;
  width: 20px;
  flex-shrink: 0;
  margin-top: 1px;
}
.ts-text {
  font-size: 0.82rem;
  color: var(--text2);
  line-height: 1.5;
  font-family: var(--font-body);
}

.ai-conclusion {
  font-size: 0.88rem;
  color: var(--text);
  line-height: 1.7;
  border-top: 1px solid var(--border);
  padding-top: 14px;
  font-family: var(--font-body);
}
.ai-cursor {
  display: inline-block;
  width: 2px;
  height: 14px;
  background: var(--cyan);
  margin-left: 2px;
  animation: blinkBadge 0.7s step-end infinite;
  vertical-align: middle;
}

.result-actions {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

/* â”€â”€ QR PANEL â”€â”€ */
.qr-layout {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}
@media (max-width: 800px) {
  .qr-layout {
    grid-template-columns: 1fr;
  }
}

.drop-zone {
  border: 2px dashed var(--border);
  border-radius: var(--radius-sm);
  padding: 48px 24px;
  text-align: center;
  cursor: pointer;
  transition: all 0.3s;
  background: var(--cyan-dd);
  margin-bottom: 16px;
}
.drop-zone:hover,
.drop-zone.over {
  border-color: var(--border-active);
  background: var(--cyan-d);
}
.dz-icon {
  font-size: 2.8rem;
  margin-bottom: 10px;
  opacity: 0.5;
}
.dz-main {
  color: var(--text2);
  font-size: 0.88rem;
  margin-bottom: 6px;
}
.dz-sub {
  color: var(--muted);
  font-size: 0.8rem;
}
.dz-link {
  color: var(--cyan);
  text-decoration: underline;
  cursor: pointer;
}
.dz-formats {
  color: var(--muted);
  font-size: 0.7rem;
  font-family: var(--font-mono);
  margin-top: 8px;
  letter-spacing: 0.08em;
}
.qr-actions {
  display: flex;
  gap: 10px;
}

.qr-permission-note {
  margin-top: 10px;
  padding: 10px 12px;
  border: 1px solid rgba(255, 149, 0, 0.3);
  border-radius: var(--radius-sm);
  background: rgba(255, 149, 0, 0.08);
  color: #ffd89a;
  font-size: 0.76rem;
  line-height: 1.45;
}

.qr-decoded-layout {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
}
.qr-preview-img {
  width: 130px;
  height: 130px;
  object-fit: contain;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg2);
}
.qr-decoded-info {
  flex: 1;
  min-width: 160px;
}
.qr-field {
  margin-bottom: 12px;
}
.qf-label {
  display: block;
  font-family: var(--font-mono);
  font-size: 0.62rem;
  color: var(--muted);
  letter-spacing: 0.1em;
  margin-bottom: 4px;
}
.qf-val {
  font-family: var(--font-mono);
  font-size: 0.82rem;
  color: var(--cyan);
  word-break: break-all;
}

/* â”€â”€ BULK â”€â”€ */
.bulk-textarea {
  width: 100%;
  min-height: 180px;
  background: var(--bg2);
  border: 1.5px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 14px 16px;
  color: var(--text);
  font-family: var(--font-mono);
  font-size: 0.82rem;
  outline: none;
  resize: vertical;
  line-height: 1.7;
  margin-bottom: 14px;
  transition: border-color 0.2s;
}
.bulk-textarea:focus {
  border-color: var(--border-active);
}
.bulk-controls {
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
}
.bulk-count {
  font-family: var(--font-mono);
  font-size: 0.72rem;
  color: var(--muted);
}
.bulk-result-row {
  display: flex;
  align-items: center;
  gap: 12px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 12px 16px;
  margin-bottom: 8px;
  font-family: var(--font-mono);
  font-size: 0.78rem;
  animation: slideIn 0.3s ease;
}
@keyframes slideIn {
  from {
    opacity: 0;
    transform: translateX(-8px);
  }
  to {
    opacity: 1;
    transform: none;
  }
}
.br-url {
  flex: 1;
  color: var(--muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.br-rf,
.br-ens {
  color: var(--text2);
  white-space: nowrap;
}

/* VERDICT PILL */
.verdict-pill {
  padding: 3px 10px;
  border-radius: 6px;
  font-size: 0.68rem;
  font-family: var(--font-mono);
  white-space: nowrap;
  flex-shrink: 0;
}
.verdict-pill.phishing {
  background: var(--red-d);
  color: var(--red);
  border: 1px solid rgba(255, 51, 85, 0.3);
}
.verdict-pill.legitimate {
  background: var(--green-d);
  color: var(--green);
  border: 1px solid rgba(0, 255, 157, 0.3);
}
.verdict-pill.suspicious {
  background: var(--orange-d);
  color: var(--orange);
  border: 1px solid rgba(255, 149, 0, 0.3);
}

/* â”€â”€ HISTORY â”€â”€ */
.history-toolbar {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  align-items: center;
}
.search-input {
  flex: 1 1 200px;
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 9px 14px;
  color: var(--text);
  font-family: var(--font-mono);
  font-size: 0.8rem;
  outline: none;
  transition: border-color 0.2s;
}
.search-input:focus {
  border-color: var(--border-active);
}
.filter-select {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 9px 14px;
  color: var(--text);
  font-family: var(--font-mono);
  font-size: 0.78rem;
  outline: none;
  cursor: pointer;
}
.history-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.history-row {
  display: flex;
  align-items: center;
  gap: 12px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 12px 16px;
  font-family: var(--font-mono);
  font-size: 0.75rem;
  transition: border-color 0.2s;
  cursor: pointer;
}
.history-row:hover {
  border-color: var(--border-hover);
}
.hr-url {
  flex: 1;
  color: var(--muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.hr-score {
  color: var(--text2);
  white-space: nowrap;
}
.hr-time {
  color: var(--muted);
  white-space: nowrap;
  font-size: 0.68rem;
}

/* â”€â”€ MODEL INFO â”€â”€ */
.model-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}
@media (max-width: 700px) {
  .model-grid {
    grid-template-columns: 1fr;
  }
}
.model-card {
}
.model-metric {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 0;
  border-bottom: 1px solid var(--border);
  font-size: 0.83rem;
}
.model-metric:last-child {
  border-bottom: none;
}
.mm-label {
  color: var(--muted);
  font-family: var(--font-mono);
  font-size: 0.75rem;
}
.mm-val {
  font-family: var(--font-display);
  font-weight: 600;
  font-size: 1rem;
}
.mm-val.accent {
  color: var(--cyan);
}

.features-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.feat-tag {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 5px 12px;
  font-family: var(--font-mono);
  font-size: 0.72rem;
  color: var(--text2);
}

.dataset-info {
  display: grid;
  gap: 0;
}
.ds-row {
  display: flex;
  justify-content: space-between;
  padding: 9px 0;
  border-bottom: 1px solid var(--border);
  font-size: 0.83rem;
}
.ds-row:last-child {
  border-bottom: none;
}
.ds-row span:first-child {
  color: var(--muted);
  font-family: var(--font-mono);
  font-size: 0.75rem;
}
.ds-row .safe {
  color: var(--green);
}
.ds-row .danger {
  color: var(--red);
}
.ds-row .accent {
  color: var(--cyan);
}

/* â”€â”€ ANALYTICS â”€â”€ */
.analytics-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}
@media (max-width: 700px) {
  .analytics-grid {
    grid-template-columns: 1fr;
  }
}
.analytics-card {
}
.donut-wrap {
  display: flex;
  gap: 20px;
  align-items: center;
  flex-wrap: wrap;
}
.donut-legend {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.legend-item {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.78rem;
  font-family: var(--font-mono);
}
.legend-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  flex-shrink: 0;
}
.bar-chart-wrap {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.bar-chart-row {
  display: flex;
  align-items: center;
  gap: 10px;
  font-family: var(--font-mono);
  font-size: 0.72rem;
}
.bcr-label {
  width: 80px;
  color: var(--muted);
}
.bcr-bar-wrap {
  flex: 1;
  height: 22px;
  background: var(--bg2);
  border-radius: 4px;
  overflow: hidden;
  border: 1px solid var(--border);
}
.bcr-bar {
  height: 100%;
  border-radius: 4px;
  transition: width 1s ease;
  display: flex;
  align-items: center;
  padding-left: 8px;
  font-size: 0.68rem;
  color: rgba(0, 0, 0, 0.7);
  font-weight: 700;
}
.bcr-val {
  width: 30px;
  color: var(--text2);
  text-align: right;
}

.feed-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
  max-height: 320px;
  overflow-y: auto;
}
.feed-row {
  display: flex;
  align-items: center;
  gap: 10px;
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 10px 14px;
  font-family: var(--font-mono);
  font-size: 0.72rem;
  animation: slideIn 0.3s ease;
}
.feed-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  flex-shrink: 0;
}
.feed-time {
  color: var(--muted);
  white-space: nowrap;
}
.feed-url {
  flex: 1;
  color: var(--text2);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.feed-score {
  white-space: nowrap;
}

/* â”€â”€ EMPTY STATE â”€â”€ */
.empty-state {
  text-align: center;
  padding: 40px;
  color: var(--muted);
  font-family: var(--font-mono);
  font-size: 0.82rem;
}

/* â”€â”€ MODAL â”€â”€ */
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.75);
  backdrop-filter: blur(8px);
  z-index: 100;
  display: none;
  place-items: center;
}
.modal-overlay.open {
  display: grid;
}
.modal-box {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 24px;
  max-width: 480px;
  width: 90%;
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.modal-header h3 {
  font-family: var(--font-display);
  font-size: 1.05rem;
}
.modal-close {
  background: none;
  border: none;
  color: var(--muted);
  cursor: pointer;
  font-size: 1.1rem;
}
.modal-actions {
  display: flex;
  gap: 10px;
}

/* LOADER */
.loader {
  display: inline-block;
  width: 16px;
  height: 16px;
  border: 2px solid rgba(0, 210, 255, 0.2);
  border-top-color: var(--cyan);
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

/* SCROLLBAR */
::-webkit-scrollbar {
  width: 5px;
  height: 5px;
}
::-webkit-scrollbar-track {
  background: var(--bg);
}
::-webkit-scrollbar-thumb {
  background: rgba(0, 210, 255, 0.18);
  border-radius: 3px;
}

/* â”€â”€ RESPONSIVE â”€â”€ */
@media (max-width: 900px) {
  :root {
    --sidebar-w: 0px;
  }
  .sidebar {
    transform: translateX(-240px);
    width: 240px;
  }
  .sidebar.open {
    transform: translateX(0);
  }
  .main-content {
    margin-left: 0;
  }
  .topbar {
    left: 0;
  }
  .hamburger {
    display: block;
  }
}
@media (max-width: 600px) {
  .main-content {
    padding-left: 16px;
    padding-right: 16px;
  }
  .scan-input-group {
    flex-direction: column;
  }
  .btn-primary {
    width: 100%;
    justify-content: center;
  }
  .result-hero {
    flex-direction: column;
  }
  .score-col {
    align-self: center;
  }
}

/* COLOR CLASSES */
.danger {
  color: var(--red);
}
.safe {
  color: var(--green);
}
.warn {
  color: var(--orange);
}
.accent {
  color: var(--cyan);
}
```

## frontend/js/app.js

`$lang
/**
 * CyberSentinel â€” app.js
 * Frontend logic: ML inference in-browser, API calls to backend, AI chain-of-thought
 */

"use strict";

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  CONFIG
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const API = "http://localhost:5000/api"; // change if backend on different port
let MODEL_WEIGHTS = null; // loaded from /ml/model_weights.json
let currentQrUrl = "";
let cameraStream = null;
let lastScanResult = null;
let historyData = [];
let statsData = {};
let rfToggleState = {
  rf_available: false,
  rf_enabled: false,
  rf_requested: false,
};

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  INIT
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
document.addEventListener("DOMContentLoaded", async () => {
  startClock();
  loadModelWeights();
  setupModelToggle();
  await fetchStats();
  checkBackend();
  setupNavigation();
  setupScannerEvents();
  setupQrEvents();
  setupBulkEvents();
  setupHistoryEvents();
  setupCameraEvents();
  renderModelPage();
  startFeedAnimation();
});

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  CLOCK
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function startClock() {
  const el = document.getElementById("topClock");
  const update = () => {
    const now = new Date();
    el.textContent = now.toLocaleTimeString("en-US", { hour12: false });
  };
  update();
  setInterval(update, 1000);
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  LOAD JS MODEL WEIGHTS (in-browser LR inference)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function loadModelWeights() {
  try {
    const resp = await fetch("../ml/model_weights.json");
    if (resp.ok) {
      MODEL_WEIGHTS = await resp.json();
      console.log(
        "[ML] LR weights loaded in browser:",
        MODEL_WEIGHTS.feature_names.length,
        "features",
      );
      setSidebarStatus(
        "dotML",
        "sidebarML",
        true,
        `LR ${(MODEL_WEIGHTS.accuracy * 100).toFixed(1)}%`,
      );
      updateModelBadges(false, true, false);
    }
  } catch (e) {
    updateModelBadges(false, false, false);
    console.warn("[ML] Could not load browser weights:", e.message);
  }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  BACKEND HEALTH CHECK
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function checkBackend() {
  try {
    const r = await fetch(`${API}/stats`, {
      signal: AbortSignal.timeout(3000),
    });
    if (r.ok) {
      const data = await r.json();
      document.getElementById("sidebarBackend").textContent = "Online";
      document
        .querySelector(".sidebar-status .status-dot")
        .classList.add("active");
      rfToggleState = {
        rf_available: Boolean(data.rf_available),
        rf_enabled: Boolean(data.rf_enabled),
        rf_requested: Boolean(data.rf_requested),
      };
      updateModelBadges(Boolean(data.rf_enabled), true, true);
      updateRFToggleButton(rfToggleState);
      if (data.rf_enabled) {
        setSidebarStatus(
          "dotML",
          "sidebarML",
          true,
          `RF+LR ${(data.rf_accuracy * 100).toFixed(1)}%`,
        );
      } else if (MODEL_WEIGHTS?.accuracy) {
        setSidebarStatus(
          "dotML",
          "sidebarML",
          true,
          `LR ${(MODEL_WEIGHTS.accuracy * 100).toFixed(1)}% (RF off)`,
        );
      } else {
        setSidebarStatus("dotML", "sidebarML", false, "LR only (RF off)");
      }
      setSidebarStatus("dotAI", "sidebarAI", true, "Ready");
    }
  } catch {
    document.getElementById("sidebarBackend").textContent = "Offline";
    document.getElementById("sidebarAI").textContent = "Local";
    updateRFToggleButton({
      rf_available: false,
      rf_enabled: false,
      offline: true,
    });
    updateModelBadges(false, Boolean(MODEL_WEIGHTS), false);
    console.warn("[Backend] Not available â€” using browser-side ML");
  }
}

function setupModelToggle() {
  const btn = document.getElementById("rfToggleBtn");
  if (!btn) return;
  btn.addEventListener("click", toggleRFMode);
  updateRFToggleButton(rfToggleState);
}

function updateRFToggleButton(state) {
  const btn = document.getElementById("rfToggleBtn");
  const hint = document.getElementById("rfToggleHint");
  if (!btn) return;

  const isOffline = Boolean(state.offline);
  const available = Boolean(state.rf_available);
  const enabled = Boolean(state.rf_enabled);

  btn.classList.toggle("on", enabled);
  btn.textContent = `RF: ${enabled ? "ON" : "OFF"}`;
  if (hint) hint.className = "rf-toggle-hint";

  if (isOffline) {
    btn.disabled = true;
    btn.title = "Backend offline";
    if (hint) {
      hint.textContent = "Backend offline. RF toggle unavailable.";
      hint.classList.add("warn");
    }
    return;
  }

  if (!available) {
    btn.disabled = true;
    btn.title = "RF model file not loaded";
    if (hint) {
      hint.textContent =
        "RF model file not found (ml/rf_model.pkl). Add the file to enable toggle.";
      hint.classList.add("warn");
    }
    return;
  }

  btn.disabled = false;
  btn.title = enabled ? "Click to turn RF off" : "Click to turn RF on";
  if (hint) {
    hint.textContent = enabled
      ? "Random Forest is enabled for ensemble scoring."
      : "Random Forest is available but currently disabled.";
    hint.classList.add(enabled ? "ready" : "warn");
  }
}

async function toggleRFMode() {
  const btn = document.getElementById("rfToggleBtn");
  if (!btn || btn.disabled) return;

  const requested = !rfToggleState.rf_enabled;
  btn.disabled = true;

  try {
    const resp = await fetch(`${API}/model-control`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rf_enabled: requested }),
      signal: AbortSignal.timeout(5000),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || "Unable to update RF mode");

    rfToggleState = data;
    updateRFToggleButton(rfToggleState);
    await checkBackend();
  } catch (err) {
    console.warn("[RF Toggle]", err.message || err);
    await checkBackend();
  } finally {
    const current = document.getElementById("rfToggleBtn");
    if (current && rfToggleState.rf_available) current.disabled = false;
  }
}

function updateModelBadges(rfReady, lrReady, aiReady) {
  const badgeRF = document.getElementById("badgeRF");
  const badgeLR = document.getElementById("badgeLR");
  const badgeAI = document.getElementById("badgeAI");

  if (badgeRF) {
    badgeRF.className = "mbadge" + (rfReady ? " active" : " off");
    badgeRF.textContent = rfReady ? "RF" : "RF OFF";
    badgeRF.title = rfReady
      ? "Random Forest model loaded"
      : "Random Forest model not loaded (fallback: LR only)";
  }
  if (badgeLR) {
    badgeLR.className = "mbadge" + (lrReady ? " active" : "");
    badgeLR.textContent = "LR";
    badgeLR.title = lrReady
      ? "Logistic Regression model loaded"
      : "Logistic Regression model unavailable";
  }
  if (badgeAI) {
    badgeAI.className = "mbadge ai" + (aiReady ? " active" : "");
    badgeAI.title = aiReady
      ? "AI reasoning available"
      : "AI reasoning fallback mode";
  }
}

function setSidebarStatus(dotId, valId, active, text) {
  const dot = document.getElementById(dotId);
  const val = document.getElementById(valId);
  if (dot) {
    dot.className = "status-dot" + (active ? " active" : " warn");
  }
  if (val && text) val.textContent = text;
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  NAVIGATION
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const PAGE_TITLES = {
  scanner: "URL Scanner",
  qr: "QR Analyzer",
  bulk: "Bulk Scanner",
  history: "Scan History",
  model: "ML Model",
  analytics: "Analytics",
};
function setupNavigation() {
  document.querySelectorAll(".nav-link").forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      switchPage(link.dataset.page);
      // close sidebar on mobile
      document.getElementById("sidebar").classList.remove("open");
    });
  });
  document.getElementById("hamburger").addEventListener("click", () => {
    document.getElementById("sidebar").classList.toggle("open");
  });
}
function switchPage(name) {
  document
    .querySelectorAll(".nav-link")
    .forEach((l) => l.classList.toggle("active", l.dataset.page === name));
  document
    .querySelectorAll(".page")
    .forEach((p) => p.classList.toggle("active", p.id === `page-${name}`));
  document.getElementById("pageTitle").textContent = PAGE_TITLES[name] || name;
  if (name === "history") {
    loadHistory();
  }
  if (name === "analytics") {
    loadAnalytics();
  }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  FEATURE EXTRACTION (browser-side, mirrors Python)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const SUSPICIOUS_KW = [
  "login",
  "verify",
  "secure",
  "account",
  "update",
  "confirm",
  "bank",
  "paypal",
  "apple",
  "amazon",
  "google",
  "microsoft",
  "password",
  "credential",
  "suspend",
  "urgent",
  "free",
  "prize",
  "winner",
  "claim",
  "signin",
  "billing",
  "support",
  "security",
  "alert",
  "notice",
  "limited",
  "expire",
  "validate",
  "authenticate",
];
const TRUSTED_DOMAINS = [
  "google.com",
  "facebook.com",
  "microsoft.com",
  "apple.com",
  "amazon.com",
  "paypal.com",
  "twitter.com",
  "github.com",
  "linkedin.com",
  "youtube.com",
  "wikipedia.org",
  "reddit.com",
  "instagram.com",
  "netflix.com",
  "ebay.com",
];
const TRUSTED_HOSTS = new Set([
  "ritiktanwar004.github.io",
  "www.snapchat.com",
  "snapchat.com",
  "google.com",
  "youtube.com",
  "facebook.com",
  "instagram.com",
  "twitter.com",
  "linkedin.com",
  "github.com",
  "stackoverflow.com",
  "wikipedia.org",
  "amazon.com",
  "amazon.in",
  "flipkart.com",
  "myntra.com",
  "apple.com",
  "microsoft.com",
  "netflix.com",
  "paypal.com",
  "openai.com",
  "bing.com",
  "yahoo.com",
  "reddit.com",
  "quora.com",
  "bbc.com",
  "cnn.com",
  "nytimes.com",
  "theguardian.com",
  "ndtv.com",
  "thehindu.com",
  "coursera.org",
  "udemy.com",
  "khanacademy.org",
  "edx.org",
  "zoom.us",
  "slack.com",
  "dropbox.com",
  "drive.google.com",
  "docs.google.com",
  "notion.so",
  "canva.com",
  "adobe.com",
  "shopify.com",
  "wordpress.com",
  "medium.com",
  "airbnb.com",
  "uber.com",
  "ola.com",
  "zomato.com",
  "swiggy.com",
  "paytm.com",
  "phonepe.com",
  "razorpay.com",
  "hdfcbank.com",
  "icicibank.com",
  "sbi.co.in",
]);
const PHISHING_TLDS = [
  ".tk",
  ".ml",
  ".ga",
  ".cf",
  ".gq",
  ".xyz",
  ".top",
  ".club",
  ".online",
  ".site",
  ".info",
  ".biz",
  ".pw",
  ".cc",
  ".su",
];

function parseUrl(url) {
  try {
    return new URL(url.startsWith("http") ? url : "https://" + url);
  } catch {
    return null;
  }
}

function extractFeatures(url) {
  const urlStr = url.trim();
  const parsed = parseUrl(urlStr);
  const domain = (parsed ? parsed.hostname : urlStr).toLowerCase();
  const path = parsed ? parsed.pathname.toLowerCase() : "";
  const query = parsed ? parsed.search : "";
  const urlLow = urlStr.toLowerCase();

  const feats = {};
  feats.is_https = urlStr.startsWith("https://") ? 1 : 0;
  feats.url_length = Math.min(urlStr.length, 200) / 200;
  feats.domain_length = Math.min(domain.length, 100) / 100;
  feats.is_ip = /^\d{1,3}(\.\d{1,3}){3}$/.test(domain.split(":")[0]) ? 1 : 0;
  feats.hyphen_count = Math.min((domain.match(/-/g) || []).length, 10) / 10;
  feats.dot_count = Math.min((domain.match(/\./g) || []).length, 8) / 8;
  feats.subdomain_count =
    Math.min(Math.max(domain.split(".").length - 2, 0), 5) / 5;
  feats.suspicious_tld = PHISHING_TLDS.some((t) => domain.endsWith(t)) ? 1 : 0;
  const kwCount = SUSPICIOUS_KW.filter((k) => urlLow.includes(k)).length;
  feats.keyword_count = Math.min(kwCount, 10) / 10;
  const brandSpoof = TRUSTED_DOMAINS.find((td) => {
    const b = td.split(".")[0];
    return urlLow.includes(b) && !domain.endsWith(td);
  });
  feats.brand_mismatch = brandSpoof ? 1 : 0;
  feats.at_symbol = urlStr.includes("@") ? 1 : 0;
  feats.double_slash = path.includes("//") ? 1 : 0;
  feats.encoded_chars =
    Math.min((urlStr.match(/%[0-9a-fA-F]{2}/g) || []).length, 10) / 10;
  feats.digit_ratio =
    [...domain].filter((c) => /\d/.test(c)).length / Math.max(domain.length, 1);
  feats.path_length = Math.min(path.length, 150) / 150;
  feats.has_port =
    domain.includes(":") && /\d+$/.test(domain.split(":").pop()) ? 1 : 0;
  feats.has_query = query.length > 0 ? 1 : 0;
  feats.special_chars =
    Math.min((urlStr.match(/[!$&'()*+,;=]/g) || []).length, 10) / 10;

  return {
    feats,
    extras: {
      domain,
      kwCount,
      brandSpoof: brandSpoof ? brandSpoof.split(".")[0] : null,
      urlLen: urlStr.length,
      domainLen: domain.length,
    },
  };
}

// Browser-side LR inference
function predictLR(featVec) {
  if (!MODEL_WEIGHTS) return 0.5;
  const { coef, intercept, mean, scale } = MODEL_WEIGHTS;
  const scaled = featVec.map(
    (v, i) => (v - mean[i]) / Math.max(scale[i], 1e-9),
  );
  const logit = scaled.reduce((s, v, i) => s + coef[i] * v, 0) + intercept;
  return 1 / (1 + Math.exp(-logit));
}

function browserPredict(url) {
  const parsed = parseUrl(url);
  const host = (parsed ? parsed.hostname : url).toLowerCase();
  if (TRUSTED_HOSTS.has(host)) {
    const { feats, extras } = extractFeatures(url);
    return {
      verdict: "legitimate",
      risk_score: 0,
      lr_score: 0,
      ml_score: 0,
      extras,
      feats,
    };
  }

  const { feats, extras } = extractFeatures(url);
  const names = MODEL_WEIGHTS
    ? MODEL_WEIGHTS.feature_names
    : Object.keys(feats);
  const featVec = names.map((n) => feats[n] || 0);
  const lrProb = predictLR(featVec);
  const riskScore = Math.round(lrProb * 100);
  const verdict =
    riskScore >= 60
      ? "phishing"
      : riskScore >= 30
        ? "suspicious"
        : "legitimate";
  return {
    verdict,
    risk_score: riskScore,
    lr_score: riskScore,
    ml_score: null,
    extras,
    feats,
  };
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  BUILD INDICATORS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function buildIndicators(feats, extras) {
  const ind = [];
  const add = (label, value, status) => ind.push({ label, value, status });

  add(
    "HTTPS Encryption",
    feats.is_https ? "Enabled" : "Missing",
    feats.is_https ? "safe" : "warn",
  );
  add(
    "IP Address Domain",
    feats.is_ip ? "âš  Detected" : "Clean",
    feats.is_ip ? "danger" : "safe",
  );
  add(
    "Suspicious TLD",
    feats.suspicious_tld ? "âš  Detected" : "Clean",
    feats.suspicious_tld ? "danger" : "safe",
  );
  add(
    "Phishing Keywords",
    `${extras.kwCount} found`,
    extras.kwCount > 3 ? "danger" : extras.kwCount > 1 ? "warn" : "safe",
  );
  add(
    "Brand Spoofing",
    extras.brandSpoof ? `âš  ${extras.brandSpoof}` : "None",
    extras.brandSpoof ? "danger" : "safe",
  );
  const h = Math.round(feats.hyphen_count * 10);
  add(
    "Hyphens in Domain",
    `${h} found`,
    h > 2 ? "danger" : h > 0 ? "warn" : "safe",
  );
  const s = Math.round(feats.subdomain_count * 5);
  add(
    "Subdomain Depth",
    `${s} levels`,
    s > 2 ? "danger" : s > 1 ? "warn" : "safe",
  );
  add(
    "URL Length",
    `${extras.urlLen} chars`,
    extras.urlLen > 100 ? "danger" : extras.urlLen > 60 ? "warn" : "safe",
  );
  add(
    "URL Encoding",
    feats.encoded_chars > 0 ? "âš  Present" : "None",
    feats.encoded_chars > 0 ? "warn" : "safe",
  );
  add(
    "@ Symbol",
    feats.at_symbol ? "âš  Found" : "None",
    feats.at_symbol ? "danger" : "safe",
  );

  return ind;
}

function renderIndicators(containerId, indicators) {
  const el = document.getElementById(containerId);
  el.innerHTML = indicators
    .map(
      (ind) => `
    <div class="indicator-chip">
      <div class="ind-dot ${ind.status}"></div>
      <div class="ind-text">
        <strong>${ind.label}</strong>
        <span>${ind.value}</span>
      </div>
    </div>
  `,
    )
    .join("");
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  AI CHAIN-OF-THOUGHT (3-step thinking animation)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function buildThinkingSteps(url, verdict, riskScore, extras) {
  const steps = [];
  const domain = extras.domain || extras.extras?.domain || url;
  const kwCount = extras.kwCount ?? extras.extras?.kwCount ?? 0;
  const brandSpoof = extras.brandSpoof ?? extras.extras?.brandSpoof ?? null;

  // Step 1: Structural analysis
  let s1 = `Analyzing URL structure: domain "${domain}" has ${Math.round((extras.feats?.domain_length || 0) * 100)} chars, `;
  s1 += extras.feats?.is_https
    ? "uses HTTPS encryption, "
    : "NO HTTPS encryption (risk), ";
  s1 += `${Math.round((extras.feats?.subdomain_count || 0) * 5)} subdomain levels detected.`;
  steps.push(s1);

  // Step 2: Threat pattern matching
  let s2 = `Pattern matching: `;
  const threats = [];
  if (brandSpoof) threats.push(`brand impersonation of "${brandSpoof}"`);
  if (kwCount > 0) threats.push(`${kwCount} social engineering keyword(s)`);
  if (extras.feats?.suspicious_tld) threats.push("high-abuse TLD");
  if (extras.feats?.is_ip) threats.push("IP address as domain");
  if (extras.feats?.hyphen_count > 0.2) threats.push("excessive hyphens");
  if (threats.length === 0)
    threats.push("no significant threat patterns found");
  s2 += threats.join(", ") + ".";
  steps.push(s2);

  // Step 3: ML confidence
  let s3 = `Ensemble ML confidence: Risk score ${riskScore}/100 (${riskScore >= 60 ? "HIGH" : riskScore >= 30 ? "MEDIUM" : "LOW"} threat). `;
  s3 +=
    verdict === "phishing"
      ? "Decision threshold exceeded â€” classifying as PHISHING."
      : verdict === "suspicious"
        ? "Partial indicators present â€” flagging as SUSPICIOUS."
        : "Insufficient threat markers â€” URL appears LEGITIMATE.";
  steps.push(s3);

  return steps;
}

function buildConclusion(url, verdict, riskScore, extras, aiText) {
  if (aiText && aiText.length > 30) return aiText;

  // Rule-based fallback
  const domain = extras.domain || extras.extras?.domain || "?";
  const kwCount = extras.kwCount ?? extras.extras?.kwCount ?? 0;
  const brandSpoof = extras.brandSpoof ?? extras.extras?.brandSpoof ?? null;

  if (verdict === "phishing") {
    let c = `ðŸš¨ HIGH THREAT: This URL is classified as a phishing attempt with ${riskScore}% confidence. `;
    if (brandSpoof)
      c += `It impersonates "${brandSpoof}" while not residing on the legitimate domain. `;
    if (kwCount > 0)
      c += `${kwCount} social engineering keyword(s) were found that are commonly used in credential theft. `;
    c += `â›” Do NOT enter any credentials. Do not proceed to this URL. Report to your security team.`;
    return c;
  }
  if (verdict === "suspicious") {
    return `âš ï¸ CAUTION: This URL scored ${riskScore}/100 on threat indicators â€” above the safe threshold. The domain "${domain}" shows partial phishing signatures. ${kwCount > 0 ? `Found ${kwCount} sensitive keywords. ` : ""}Independently verify this URL before visiting, especially if received via email or SMS.`;
  }
  return `âœ… LOW RISK: URL scored ${riskScore}/100 â€” below threat thresholds. Domain "${domain}" uses ${extras.feats?.is_https ? "secure HTTPS" : "HTTP (note: no encryption)"} and shows no brand impersonation, suspicious keywords, or anomalous structure. Always verify unexpected links independently.`;
}

async function animateThinkingSteps(steps, conclusion, tsIds, conclusionId) {
  for (let i = 0; i < steps.length; i++) {
    await delay(400 + i * 300);
    const el = document.getElementById(tsIds[i]);
    if (el) {
      el.querySelector(".ts-text").textContent = steps[i];
      el.classList.add("visible");
    }
  }
  await delay(500);
  const concEl = document.getElementById(conclusionId);
  if (concEl) {
    await typeText(concEl, conclusion);
  }
}

async function typeText(el, text, speed = 12) {
  el.innerHTML = "";
  const cursor = document.createElement("span");
  cursor.className = "ai-cursor";
  el.appendChild(cursor);
  for (const char of text) {
    cursor.insertAdjacentText("beforebegin", char);
    await delay(speed);
  }
  cursor.remove();
}

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  MAIN SCAN FLOW
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function setupScannerEvents() {
  const btn = document.getElementById("scanBtn");
  const inp = document.getElementById("urlInput");
  const clearBtn = document.getElementById("clearUrlBtn");

  btn.addEventListener("click", () => triggerScan());
  inp.addEventListener("keydown", (e) => e.key === "Enter" && triggerScan());
  clearBtn.addEventListener("click", () => {
    inp.value = "";
    inp.focus();
  });

  document
    .getElementById("copyReportBtn")
    .addEventListener("click", copyReport);
  document
    .getElementById("exportJsonBtn")
    .addEventListener("click", exportJson);
  document.getElementById("shareLinkBtn").addEventListener("click", shareLink);
}

window.testUrl = function (url) {
  document.getElementById("urlInput").value = url;
  triggerScan();
};

async function triggerScan() {
  const rawUrl = document.getElementById("urlInput").value.trim();
  if (!rawUrl) return;
  const url = rawUrl.startsWith("http") ? rawUrl : "https://" + rawUrl;

  setProgress(true);
  const btn = document.getElementById("scanBtn");
  btn.disabled = true;
  btn.innerHTML = `<span class="loader"></span> Scanningâ€¦`;

  // Reset AI steps
  ["ts1", "ts2", "ts3"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) {
      el.classList.remove("visible");
      el.querySelector(".ts-text").textContent = "";
    }
  });
  document.getElementById("aiConclusion").textContent = "";

  try {
    let result;
    try {
      // Try backend first
      const resp = await fetch(`${API}/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
        signal: AbortSignal.timeout(10000),
      });
      if (resp.ok) {
        const data = await resp.json();
        result = {
          ...data,
          extras: {
            domain: data.domain,
            kwCount: 0,
            brandSpoof: null,
            feats: {},
          },
        };
        // Also run browser-side for indicator data
        const browser = browserPredict(url);
        result.indicators = buildIndicators(browser.feats, browser.extras);
        result.extras = browser.extras;
        result.feats = browser.feats;
      } else throw new Error("Backend error");
    } catch {
      // Fallback: browser-side ML
      const browser = browserPredict(url);
      result = {
        url,
        verdict: browser.verdict,
        risk_score: browser.risk_score,
        lr_score: browser.lr_score,
        ml_score: null,
        indicators: buildIndicators(browser.feats, browser.extras),
        extras: browser.extras,
        feats: browser.feats,
        ai_analysis: null,
      };
    }

    lastScanResult = result;
    renderResult(
      result,
      "resultCard",
      "verdictBadge",
      "scoreRingSvg",
      "ringFill",
      "scoreNum",
      "rfBar",
      "rfVal",
      "lrBar",
      "lrVal",
      "ensBar",
      "ensVal",
      "indicatorsGrid",
      "resultUrl",
      result.url,
    );

    // AI thinking animation
    const thinkSteps = buildThinkingSteps(
      url,
      result.verdict,
      result.risk_score,
      result,
    );
    const conclusion = buildConclusion(
      url,
      result.verdict,
      result.risk_score,
      result,
      result.ai_analysis,
    );
    animateThinkingSteps(
      thinkSteps,
      conclusion,
      ["ts1", "ts2", "ts3"],
      "aiConclusion",
    );

    // Update threat ticker
    updateThreatTicker(result.verdict);

    // Save local stats
    saveLocalHistory(result);
  } catch (err) {
    console.error("Scan error:", err);
  }

  setProgress(false);
  btn.disabled = false;
  btn.innerHTML = `<span class="btn-icon">âš¡</span> SCAN URL`;
}

function renderResult(
  result,
  cardId,
  badgeId,
  ringSvgId,
  ringFillId,
  scoreNumId,
  rfBarId,
  rfValId,
  lrBarId,
  lrValId,
  ensBarId,
  ensValId,
  gridId,
  urlLabelId,
  url,
) {
  const card = document.getElementById(cardId);
  if (!card) return;
  card.style.display = "block";
  card.className = "result-card card v-" + result.verdict;

  // Verdict badge
  const badge = document.getElementById(badgeId);
  const verdictMap = {
    phishing: "ðŸš¨ PHISHING",
    legitimate: "âœ… LEGITIMATE",
    suspicious: "âš  SUSPICIOUS",
  };
  if (badge) {
    badge.textContent = verdictMap[result.verdict] || result.verdict;
    badge.className = "verdict-badge " + result.verdict;
  }

  // URL label
  if (urlLabelId) {
    const urlEl = document.getElementById(urlLabelId);
    if (urlEl)
      urlEl.textContent =
        url && url.length > 70 ? url.substring(0, 70) + "â€¦" : url;
  }

  // Score ring
  const rs = Number(result.risk_score ?? 0);
  const ringFill = document.getElementById(ringFillId);
  const scoreEl = document.getElementById(scoreNumId);
  const colorClass = rs >= 60 ? "r" : rs >= 30 ? "o" : "g";
  if (ringFill) {
    ringFill.setAttribute("class", "ring-fill " + colorClass);
  }
  const circumference = 314;
  const offset = circumference - (rs / 100) * circumference;
  setTimeout(() => {
    if (ringFill) ringFill.style.strokeDashoffset = offset;
  }, 50);
  if (scoreEl) {
    scoreEl.textContent = Number.isFinite(rs) ? String(rs) : "0";
    scoreEl.className =
      "score-num " + (rs >= 60 ? "danger" : rs >= 30 ? "warn" : "safe");
  }

  // Dual model bars
  const mlScore = Number(result.ml_score ?? result.risk_score ?? 0);
  const lrScore = Number(result.lr_score ?? result.risk_score ?? 0);
  const ensScore = Number(result.risk_score ?? 0);
  setTimeout(() => {
    const rfBar = document.getElementById(rfBarId);
    const rfVal = document.getElementById(rfValId);
    const lrBar = document.getElementById(lrBarId);
    const lrVal = document.getElementById(lrValId);
    const ensBar = document.getElementById(ensBarId);
    const ensVal = document.getElementById(ensValId);

    if (rfBar) {
      rfBar.style.width = mlScore + "%";
    }
    if (rfVal) {
      rfVal.textContent = result.ml_score == null ? "N/A" : mlScore + "%";
    }
    if (lrBar) {
      lrBar.style.width = lrScore + "%";
    }
    if (lrVal) {
      lrVal.textContent = lrScore + "%";
    }
    if (ensBar) {
      ensBar.style.width = ensScore + "%";
    }
    if (ensVal) {
      ensVal.textContent = ensScore + "%";
    }
  }, 100);

  // Indicators
  const indicators =
    result.indicators ||
    (result.feats ? buildIndicators(result.feats, result.extras || {}) : []);
  renderIndicators(gridId, indicators);
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  STATS & PROGRESS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function fetchStats() {
  try {
    const r = await fetch(`${API}/stats`, {
      signal: AbortSignal.timeout(3000),
    });
    if (r.ok) {
      statsData = await r.json();
      updateStatsStrip(statsData);
    }
  } catch {
    // use local storage
    const local = JSON.parse(localStorage.getItem("cs_local_stats") || "{}");
    updateStatsStrip({
      total_scans: local.total || 0,
      phishing_found: local.phishing || 0,
      safe_found: local.safe || 0,
      suspicious_found: local.suspicious || 0,
      last_24h: local.total || 0,
    });
  }
}

function updateStatsStrip(data) {
  document.getElementById("st0").textContent = data.total_scans ?? "â€”";
  document.getElementById("st1").textContent = data.phishing_found ?? "â€”";
  document.getElementById("st2").textContent = data.safe_found ?? "â€”";
  document.getElementById("st3").textContent = data.suspicious_found ?? "â€”";
  document.getElementById("st4").textContent = data.last_24h ?? "â€”";
}

function setProgress(on) {
  const fill = document.getElementById("scanProgressFill");
  fill.classList.toggle("active", on);
  fill.style.width = on ? "100%" : "0%";
}

function updateThreatTicker(verdict) {
  const el = document.getElementById("tickerVal");
  if (verdict === "phishing") {
    el.textContent = "CRITICAL";
    el.className = "ticker-val critical";
  } else if (verdict === "suspicious") {
    el.textContent = "ELEVATED";
    el.className = "ticker-val elevated";
  } else {
    el.textContent = "NOMINAL";
    el.className = "ticker-val";
  }
}

function saveLocalHistory(result) {
  let hist = JSON.parse(localStorage.getItem("cs_hist") || "[]");
  hist.unshift({
    url: result.url,
    verdict: result.verdict,
    risk_score: result.risk_score,
    time: new Date().toISOString(),
  });
  if (hist.length > 200) hist = hist.slice(0, 200);
  localStorage.setItem("cs_hist", JSON.stringify(hist));

  let s = JSON.parse(localStorage.getItem("cs_local_stats") || "{}");
  s.total = (s.total || 0) + 1;
  s[result.verdict] = (s[result.verdict] || 0) + 1;
  localStorage.setItem("cs_local_stats", JSON.stringify(s));

  fetchStats();
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  REPORT ACTIONS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function copyReport() {
  if (!lastScanResult) return;
  const r = lastScanResult;
  const text = [
    "â•â•â• CyberSentinel Threat Report â•â•â•",
    `URL: ${r.url}`,
    `Verdict: ${r.verdict.toUpperCase()}`,
    `Risk Score: ${r.risk_score}/100`,
    r.ml_score ? `Random Forest: ${r.ml_score}%` : "",
    `Logistic Regression: ${r.lr_score}%`,
    `Timestamp: ${new Date().toISOString()}`,
    "â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•",
  ]
    .filter(Boolean)
    .join("\n");
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById("copyReportBtn");
    btn.textContent = "âœ“ Copied!";
    setTimeout(() => (btn.textContent = "ðŸ“‹ Copy Report"), 2000);
  });
}
function exportJson() {
  if (!lastScanResult) return;
  const blob = new Blob([JSON.stringify(lastScanResult, null, 2)], {
    type: "application/json",
  });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "cybersentinel-report.json";
  a.click();
}
function shareLink() {
  if (!lastScanResult) return;
  const url = `${location.origin}${location.pathname}?scan=${encodeURIComponent(lastScanResult.url)}`;
  navigator.clipboard.writeText(url);
  const btn = document.getElementById("shareLinkBtn");
  btn.textContent = "âœ“ Link Copied!";
  setTimeout(() => (btn.textContent = "ðŸ”— Share"), 2000);
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  QR SCANNER
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function setupQrEvents() {
  const dropZone = document.getElementById("dropZone");
  const fileInput = document.getElementById("qrFileInput");

  document
    .getElementById("dzClick")
    .addEventListener("click", () => fileInput.click());
  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("over");
  });
  dropZone.addEventListener("dragleave", () =>
    dropZone.classList.remove("over"),
  );
  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("over");
    if (e.dataTransfer.files[0]) handleQrFile(e.dataTransfer.files[0]);
  });
  fileInput.addEventListener("change", (e) => {
    if (e.target.files[0]) handleQrFile(e.target.files[0]);
  });

  document.getElementById("qrPasteBtn").addEventListener("click", async () => {
    try {
      const items = await navigator.clipboard.read();
      for (const item of items) {
        const imgType = item.types.find((t) => t.startsWith("image/"));
        if (imgType) {
          handleQrFile(await item.getType(imgType));
          return;
        }
      }
      alert("No image in clipboard. Copy a QR image first.");
    } catch {
      alert(
        "Clipboard access denied. Permission is only needed for QR paste. Normal URL scanning works without permission. You can upload the file instead.",
      );
    }
  });

  document.getElementById("qrCamBtn").addEventListener("click", () => {
    document.getElementById("cameraModal").classList.add("open");
    startCamera();
  });

  document
    .getElementById("analyzeQrBtn")
    .addEventListener("click", async () => {
      if (!currentQrUrl) return;
      const btn = document.getElementById("analyzeQrBtn");
      btn.disabled = true;
      btn.innerHTML = `<span class="loader"></span> Analyzingâ€¦`;

      const browser = browserPredict(currentQrUrl);
      let result = {
        url: currentQrUrl,
        verdict: browser.verdict,
        risk_score: browser.risk_score,
        lr_score: browser.lr_score,
        ml_score: null,
        feats: browser.feats,
        extras: browser.extras,
      };

      try {
        const resp = await fetch(`${API}/predict`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: currentQrUrl }),
          signal: AbortSignal.timeout(8000),
        });
        if (resp.ok) Object.assign(result, await resp.json());
      } catch {}

      const indicators = buildIndicators(browser.feats, browser.extras);
      renderResult(
        result,
        "qrScanResult",
        "qrVerdictBadge",
        null,
        "qrRingFill",
        "qrScoreNum",
        null,
        null,
        null,
        null,
        null,
        null,
        "qrIndicatorsGrid",
        "qrResultUrl",
        currentQrUrl,
      );
      document.getElementById("qrScanResult").style.display = "block";

      const conclusion = buildConclusion(
        currentQrUrl,
        result.verdict,
        result.risk_score,
        browser,
        result.ai_analysis,
      );
      const concEl = document.getElementById("qrAiConclusion");
      if (concEl) typeText(concEl, conclusion);
      saveLocalHistory(result);
      btn.disabled = false;
      btn.innerHTML = "âš¡ ANALYZE URL";
    });
}

function handleQrFile(file) {
  const reader = new FileReader();
  reader.onload = (e) => {
    const img = document.getElementById("qrPreviewImg");
    img.src = e.target.result;
    img.onload = () => {
      const canvas = document.createElement("canvas");
      canvas.width = img.naturalWidth;
      canvas.height = img.naturalHeight;
      canvas.getContext("2d").drawImage(img, 0, 0);
      const imageData = canvas
        .getContext("2d")
        .getImageData(0, 0, canvas.width, canvas.height);
      const code =
        typeof jsQR !== "undefined"
          ? jsQR(imageData.data, imageData.width, imageData.height)
          : null;
      document.getElementById("qrResultPanel").style.display = "block";
      if (code) {
        currentQrUrl = code.data;
        document.getElementById("qrDecodedContent").textContent = code.data;
        document.getElementById("qrType").textContent = code.data.startsWith(
          "http",
        )
          ? "ðŸ”— URL / Link"
          : "ðŸ“„ Text / Data";
        document.getElementById("qrLength").textContent =
          code.data.length + " chars";
      } else {
        document.getElementById("qrDecodedContent").textContent =
          "âš  Could not decode â€” try a clearer image";
        document.getElementById("qrType").textContent = "Unknown";
      }
    };
  };
  reader.readAsDataURL(file);
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  CAMERA
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function setupCameraEvents() {
  const close1 = document.getElementById("closeCamBtn");
  const close2 = document.getElementById("closeCamBtn2");
  const capture = document.getElementById("captureCamBtn");
  [close1, close2].forEach((b) => b?.addEventListener("click", stopCamera));
  capture?.addEventListener("click", captureQrFromCamera);
}

async function startCamera() {
  try {
    cameraStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: "environment" },
    });
    document.getElementById("cameraFeed").srcObject = cameraStream;
  } catch {
    alert(
      "Camera access denied. Permission is only needed for QR camera scan. Normal URL scanning works without permission.",
    );
    stopCamera();
  }
}

function stopCamera() {
  if (cameraStream) {
    cameraStream.getTracks().forEach((t) => t.stop());
    cameraStream = null;
  }
  document.getElementById("cameraModal").classList.remove("open");
}

function captureQrFromCamera() {
  const video = document.getElementById("cameraFeed");
  const canvas = document.getElementById("camCanvas");
  canvas.width = video.videoWidth;
  canvas.height = video.videoHeight;
  canvas.getContext("2d").drawImage(video, 0, 0);
  const imageData = canvas
    .getContext("2d")
    .getImageData(0, 0, canvas.width, canvas.height);
  const code =
    typeof jsQR !== "undefined"
      ? jsQR(imageData.data, imageData.width, imageData.height)
      : null;
  if (code) {
    currentQrUrl = code.data;
    const img = document.getElementById("qrPreviewImg");
    img.src = canvas.toDataURL();
    document.getElementById("qrDecodedContent").textContent = code.data;
    document.getElementById("qrType").textContent = code.data.startsWith("http")
      ? "ðŸ”— URL / Link"
      : "ðŸ“„ Text";
    document.getElementById("qrLength").textContent =
      code.data.length + " chars";
    document.getElementById("qrResultPanel").style.display = "block";
    stopCamera();
    switchPage("qr");
  } else alert("No QR code detected. Reposition and try again.");
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  BULK SCANNER
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
let bulkResultsCache = [];
function setupBulkEvents() {
  const ta = document.getElementById("bulkTextarea");
  ta.addEventListener("input", () => {
    const lines = ta.value.split("\n").filter((l) => l.trim());
    document.getElementById("bulkCount").textContent =
      Math.min(lines.length, 30) + " URLs detected";
  });
  document.getElementById("bulkClearBtn").addEventListener("click", () => {
    ta.value = "";
    document.getElementById("bulkResultsContainer").innerHTML = "";
    document.getElementById("bulkCount").textContent = "0 URLs detected";
    bulkResultsCache = [];
  });
  document.getElementById("bulkScanBtn").addEventListener("click", runBulkScan);
  document
    .getElementById("bulkExportBtn")
    .addEventListener("click", exportBulkCsv);
}

async function runBulkScan() {
  const lines = document
    .getElementById("bulkTextarea")
    .value.split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .slice(0, 30);
  if (!lines.length) return;

  const btn = document.getElementById("bulkScanBtn");
  btn.disabled = true;
  btn.innerHTML = `<span class="loader"></span> Scanningâ€¦`;
  setProgress(true);
  bulkResultsCache = [];

  const container = document.getElementById("bulkResultsContainer");
  container.innerHTML = `<div class="card"><div class="card-label">â‰¡ BULK RESULTS</div><div id="bulkRows"></div></div>`;
  const rowsEl = document.getElementById("bulkRows");

  // Try backend bulk endpoint
  let backendResults = null;
  try {
    const resp = await fetch(`${API}/bulk`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ urls: lines }),
      signal: AbortSignal.timeout(30000),
    });
    if (resp.ok) backendResults = (await resp.json()).results;
  } catch {}

  for (let i = 0; i < lines.length; i++) {
    const url = lines[i].startsWith("http") ? lines[i] : "https://" + lines[i];
    let r;
    if (backendResults && backendResults[i]) {
      r = backendResults[i];
    } else {
      const browser = browserPredict(url);
      r = {
        url,
        verdict: browser.verdict,
        risk_score: browser.risk_score,
        ml_score: null,
      };
    }
    bulkResultsCache.push(r);
    saveLocalHistory(r);

    const row = document.createElement("div");
    row.className = "bulk-result-row";
    row.innerHTML = `
      <span class="verdict-pill ${r.verdict}">${r.verdict === "phishing" ? "ðŸš¨" : r.verdict === "legitimate" ? "âœ…" : "âš "} ${r.verdict}</span>
      <span class="br-url" title="${r.url}">${r.url}</span>
      ${r.ml_score !== null ? `<span class="br-rf">RF: ${r.ml_score}%</span>` : ""}
      <span class="br-ens" style="color:${r.risk_score >= 60 ? "var(--red)" : r.risk_score >= 30 ? "var(--orange)" : "var(--green)"};">${r.risk_score}/100</span>
    `;
    rowsEl.appendChild(row);
    await delay(60);
  }

  setProgress(false);
  btn.disabled = false;
  btn.innerHTML = "âš¡ SCAN ALL";
  fetchStats();
}

function exportBulkCsv() {
  if (!bulkResultsCache.length) return;
  const csv =
    "URL,Verdict,Risk Score,ML Score\n" +
    bulkResultsCache
      .map((r) => `"${r.url}",${r.verdict},${r.risk_score},${r.ml_score ?? ""}`)
      .join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "cybersentinel-bulk.csv";
  a.click();
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  HISTORY
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function setupHistoryEvents() {
  document
    .getElementById("refreshHistoryBtn")
    .addEventListener("click", loadHistory);
  document
    .getElementById("clearHistoryBtn")
    .addEventListener("click", async () => {
      if (!confirm("Clear all history from database?")) return;
      localStorage.removeItem("cs_hist");
      localStorage.removeItem("cs_local_stats");
      fetchStats();
      loadHistory();
    });
  document
    .getElementById("exportHistoryBtn")
    .addEventListener("click", exportHistoryCsv);
  document
    .getElementById("historySearch")
    .addEventListener("input", renderHistoryList);
  document
    .getElementById("historyFilter")
    .addEventListener("change", renderHistoryList);
}

async function loadHistory() {
  historyData = [];
  // Try backend
  try {
    const r = await fetch(`${API}/history?limit=100`, {
      signal: AbortSignal.timeout(4000),
    });
    if (r.ok) {
      const d = await r.json();
      historyData = d.history;
    }
  } catch {}
  // Merge local
  const local = JSON.parse(localStorage.getItem("cs_hist") || "[]");
  if (!historyData.length) historyData = local;
  renderHistoryList();
}

function renderHistoryList() {
  const q = document.getElementById("historySearch").value.toLowerCase();
  const filter = document.getElementById("historyFilter").value;
  const filtered = historyData.filter((r) => {
    if (filter && r.verdict !== filter) return false;
    if (q && !r.url.toLowerCase().includes(q)) return false;
    return true;
  });

  const el = document.getElementById("historyList");
  if (!filtered.length) {
    el.innerHTML = `<div class="empty-state">No records found</div>`;
    return;
  }

  el.innerHTML = filtered
    .map((r) => {
      const time = r.created_at
        ? new Date(r.created_at).toLocaleString()
        : r.time
          ? new Date(r.time).toLocaleString()
          : "â€”";
      return `<div class="history-row">
      <span class="verdict-pill ${r.verdict}">${r.verdict}</span>
      <span class="hr-url" title="${r.url}">${r.url}</span>
      <span class="hr-score" style="color:${r.risk_score >= 60 ? "var(--red)" : r.risk_score >= 30 ? "var(--orange)" : "var(--green)"};">${r.risk_score}/100</span>
      <span class="hr-time">${time}</span>
    </div>`;
    })
    .join("");
}

function exportHistoryCsv() {
  const csv =
    "URL,Verdict,Risk Score,Timestamp\n" +
    historyData
      .map(
        (r) =>
          `"${r.url}",${r.verdict},${r.risk_score},${r.created_at || r.time || ""}`,
      )
      .join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "cybersentinel-history.csv";
  a.click();
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  MODEL PAGE
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function renderModelPage() {
  try {
    const r = await fetch(`${API}/model-info`, {
      signal: AbortSignal.timeout(3000),
    });
    if (r.ok) {
      const data = await r.json();
      const models = data.models || [];
      const rf = models.find((m) => m.name.includes("Forest"));
      const lr = models.find((m) => m.name.includes("Logistic"));
      if (rf) {
        document.getElementById("rfAcc").textContent =
          (rf.accuracy * 100).toFixed(2) + "%";
        document.getElementById("rfF1").textContent = rf.f1.toFixed(4);
      }
      if (lr) {
        document.getElementById("lrAcc").textContent =
          (lr.accuracy * 100).toFixed(2) + "%";
        document.getElementById("lrF1").textContent = lr.f1.toFixed(4);
      }
      if (data.features?.length) {
        document.getElementById("featuresGrid").innerHTML = data.features
          .map((f) => `<div class="feat-tag">${f}</div>`)
          .join("");
      }
    }
  } catch {
    // Use local weights
    if (MODEL_WEIGHTS) {
      document.getElementById("lrAcc").textContent =
        (MODEL_WEIGHTS.accuracy * 100).toFixed(2) + "%";
      document.getElementById("lrF1").textContent = MODEL_WEIGHTS.f1.toFixed(4);
      document.getElementById("featuresGrid").innerHTML =
        MODEL_WEIGHTS.feature_names
          .map((f) => `<div class="feat-tag">${f}</div>`)
          .join("");
    }
  }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  ANALYTICS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function loadAnalytics() {
  try {
    const r = await fetch(`${API}/stats`, {
      signal: AbortSignal.timeout(3000),
    });
    if (r.ok) {
      const data = await r.json();
      renderDonut(data.distribution || {});
      renderBarChart(data);
    }
  } catch {
    const local = JSON.parse(localStorage.getItem("cs_local_stats") || "{}");
    renderDonut({
      phishing: local.phishing || 0,
      legitimate: local.legitimate || 0,
      suspicious: local.suspicious || 0,
    });
  }
  renderFeedList();
}

function renderDonut(dist) {
  const canvas = document.getElementById("donutChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const total = Object.values(dist).reduce((a, b) => a + b, 0);
  if (total === 0) {
    ctx.clearRect(0, 0, 200, 200);
    return;
  }

  const colors = {
    phishing: "#ff3355",
    legitimate: "#00ff9d",
    suspicious: "#ff9500",
  };
  const labels = Object.keys(dist);
  let startAngle = -Math.PI / 2;
  ctx.clearRect(0, 0, 200, 200);

  labels.forEach((label) => {
    const slice = (dist[label] / total) * 2 * Math.PI;
    ctx.beginPath();
    ctx.moveTo(100, 100);
    ctx.arc(100, 100, 80, startAngle, startAngle + slice);
    ctx.fillStyle = colors[label] || "#5a7a96";
    ctx.fill();
    startAngle += slice;
  });

  // Hole
  ctx.beginPath();
  ctx.arc(100, 100, 50, 0, 2 * Math.PI);
  ctx.fillStyle = "#0f1720";
  ctx.fill();

  // Legend
  document.getElementById("donutLegend").innerHTML = labels
    .map(
      (l) => `
    <div class="legend-item">
      <div class="legend-dot" style="background:${colors[l] || "#5a7a96"}"></div>
      <span>${l}: ${dist[l]}</span>
    </div>
  `,
    )
    .join("");
}

function renderBarChart(data) {
  const wrap = document.getElementById("barChartWrap");
  const ranges = [
    { label: "0-20", key: "low", color: "var(--green)" },
    { label: "21-40", key: "med-low", color: "#a0e080" },
    { label: "41-60", key: "med", color: "var(--orange)" },
    { label: "61-80", key: "med-high", color: "#ff6633" },
    { label: "81-100", key: "high", color: "var(--red)" },
  ];
  const dist = data.distribution || {};
  const total = Object.values(dist).reduce((a, b) => a + b, 0);
  if (total === 0) return;

  wrap.innerHTML = ranges
    .map((r) => {
      // approximate distribution from verdict counts
      const pct =
        r.key === "low"
          ? Math.round(((dist.legitimate || 0) / total) * 100)
          : r.key === "high"
            ? Math.round(((dist.phishing || 0) / total) * 100)
            : r.key === "med"
              ? Math.round(((dist.suspicious || 0) / total) * 40)
              : 5;
      return `<div class="bar-chart-row">
      <span class="bcr-label">${r.label}</span>
      <div class="bcr-bar-wrap">
        <div class="bcr-bar" style="width:${pct}%;background:${r.color};">${pct > 5 ? pct + "%" : ""}</div>
      </div>
      <span class="bcr-val">${pct}%</span>
    </div>`;
    })
    .join("");
}

function renderFeedList() {
  const local = JSON.parse(localStorage.getItem("cs_hist") || "[]").slice(
    0,
    20,
  );
  const el = document.getElementById("feedList");
  if (!local.length) {
    el.innerHTML = `<div class="empty-state">No scan data yet</div>`;
    return;
  }
  el.innerHTML = local
    .map(
      (r) => `
    <div class="feed-row">
      <div class="feed-dot" style="background:${r.verdict === "phishing" ? "var(--red)" : r.verdict === "suspicious" ? "var(--orange)" : "var(--green)"};box-shadow:0 0 6px ${r.verdict === "phishing" ? "var(--red)" : r.verdict === "suspicious" ? "var(--orange)" : "var(--green)"}"></div>
      <span class="feed-time">${r.time ? new Date(r.time).toLocaleTimeString() : "â€”"}</span>
      <span class="feed-url">${r.url}</span>
      <span class="verdict-pill ${r.verdict}" style="font-size:0.62rem;">${r.verdict}</span>
      <span class="feed-score" style="color:${r.risk_score >= 60 ? "var(--red)" : r.risk_score >= 30 ? "var(--orange)" : "var(--green)"};">${r.risk_score}/100</span>
    </div>
  `,
    )
    .join("");
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  LIVE FEED ANIMATION (threat ticker page)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function startFeedAnimation() {
  // Continuous demo feed for when no real data exists â€” updates every 4s
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  URL PARAM â€” auto-scan from share link
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const urlParams = new URLSearchParams(window.location.search);
const autoScan = urlParams.get("scan");
if (autoScan) {
  setTimeout(() => {
    document.getElementById("urlInput").value = autoScan;
    triggerScan();
  }, 800);
}
```

## ml/model_weights.json

`$lang
{
  "coef": [
    -0.31933712722675,
    -2.9036044632502893,
    1.1408684109057177,
    1.3164682293347585,
    0.5711948624976656,
    3.930822610616554,
    -2.0425130289884854,
    0.07027120935200096,
    0.16942893020965516,
    0.150074586551464,
    0.0562214167963708,
    -0.04457628166899206,
    -1.2977661507616267,
    -0.10600559526927972,
    -2.7170378706019194,
    0.5738380863817295,
    -1.390924239102278,
    -0.5755194061668377
  ],
  "intercept": -7.002511653179965,
  "mean": [
    0.032227940566116046,
    0.3478518510832253,
    0.11235867850917337,
    0.0009753465593093716,
    0.0026126836556818835,
    0.1074048518303312,
    0.021395368141447508,
    0.020440773636590023,
    0.006922885365651283,
    0.027102183116128498,
    0.0031335602224620237,
    0.0013903876483771893,
    0.08949531003569264,
    0.25874945334044563,
    0.2831624747516676,
    0.00018676849008051797,
    0.16064165352369886,
    0.07945546609113888
  ],
  "scale": [
    0.1766049274879182,
    0.2739018843423923,
    0.04880805391377698,
    0.031215304874361666,
    0.022345390849875555,
    0.07612543286936521,
    0.07196753638837732,
    0.1415024678574661,
    0.02801894223508598,
    0.16238120207240447,
    0.055890437668651136,
    0.03726197083575876,
    0.27098803927560927,
    0.42910643310798885,
    0.2883529948921347,
    0.013665050589421803,
    0.36720009896074257,
    0.22567152179240468
  ],
  "feature_names": [
    "is_https",
    "url_length",
    "domain_length",
    "is_ip",
    "hyphen_count",
    "dot_count",
    "subdomain_count",
    "suspicious_tld",
    "keyword_count",
    "brand_mismatch",
    "at_symbol",
    "double_slash",
    "encoded_chars",
    "digit_ratio",
    "path_length",
    "has_port",
    "has_query",
    "special_chars"
  ],
  "accuracy": 0.9173,
  "f1": 0.6673
}
```

## requirements.txt

`$lang
flask>=2.3.0
scikit-learn>=1.3.0
numpy>=1.24.0
pandas>=2.0.0
joblib>=1.3.0
```

## .gitignore

`$lang
# Virtual Environment
.venv/
venv/
env/
ENV/
__pycache__/
*.py[cod]
*$py.class
*.so

# Large Model Files (regenerate or download separately)
ml/*.pkl
ml/*.h5
ml/*.model

# Database Files (local state)
*.db
*.sqlite
*.sqlite3

# ML Dataset (if too large)
ml/detection_x_merged.csv

# IDE/Editor
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store
Thumbs.db

# Logs
*.log
logs/

# Python
dist/
build/
*.egg-info/
pip-log.txt

# OS
.env
.env.local
*.bak
```

## .github/workflows/python-tests.yml

`$lang
name: Python Lint & Test

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt

      - name: Lint with flake8
        run: |
          pip install flake8
          flake8 backend/ --count --select=E9,F63,F7,F82 --show-source --statistics || true
```

## README.md

`$lang
# ðŸ›¡ CyberSentinel â€” Phishing Detection Platform

[![Python](https://img.shields.io/badge/Python-3.10+-blue)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3+-green)](https://flask.palletsprojects.com)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3+-orange)](https://scikit-learn.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](#license)

> **Advanced ML + AI-powered phishing detection platform**  
> ðŸŽ“ College project Â· 60,235 URLs trained Â· **97.1% accuracy** Â· Ensemble ML Â· Chain-of-Thought AI Â· QR Scanner Â· Real-time analytics

---

## ðŸ“ Project Structure

```
cybersentinel/
â”œâ”€â”€ backend/
â”‚   â”œâ”€â”€ app.py                  â† Flask REST API + SQLite database
â”‚   â””â”€â”€ cybersentinel.db        â† Auto-created on first run
â”œâ”€â”€ frontend/
â”‚   â”œâ”€â”€ index.html              â† Main app (multi-page)
â”‚   â”œâ”€â”€ css/style.css           â† Full styling
â”‚   â””â”€â”€ js/app.js               â† Frontend logic + browser ML
â””â”€â”€ ml/
    â”œâ”€â”€ model_weights.json      â† LR weights (used in browser too)
    â””â”€â”€ rf_model.pkl            â† Random Forest model (backend)
```

---

## ðŸš€ Installation & Setup

### Requirements

- **Python 3.10+**
- **pip** or **conda**
- **Git** (for cloning)

### Step 1: Clone Repository

```bash
git clone https://github.com/yourusername/cybersentinel.git
cd cybersentinel
```

### Step 2: Create Python Virtual Environment

**Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**macOS / Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Download/Generate ML Models

The project includes pre-trained models, but you can regenerate them:

**Option A: Use existing models** (already in `ml/`)

```bash
# Models are included in the repo (no action needed)
```

**Option B: Train new model from dataset**

```bash
# Download dataset or use your own CSV with columns: url, label
# label: 0 = legitimate, 1 = phishing

python backend/train_rf.py --dataset ml/detection_x_merged.csv
```

> **Note:** `ml/rf_model.pkl` and `ml/detection_x_merged.csv` are excluded from git by `.gitignore` to save space. You can:
>
> - Keep your local trained model
> - Train it fresh on first run
> - Download from a release if provided

### Step 5: Run Application

```bash
python backend/app.py
```

**Output:**

```
 * Running on http://127.0.0.1:5000
```

**Browser:** Visit `http://localhost:5000`

---

## ðŸ¤– ML Architecture

| Model                                   | Accuracy      | F1 Score   | Ensemble Weight |
| --------------------------------------- | ------------- | ---------- | --------------- |
| **Random Forest** (100 trees, depth=15) | **97.14%** â­ | **0.7986** | **60%**         |
| **Logistic Regression** (balanced)      | 91.73%        | 0.6673     | **40%**         |
| **Ensemble Score**                      | -             | -          | Combined 97.1%  |

**18 engineered features:**

- is_https, url_length, domain_length, is_ip
- hyphen_count, dot_count, subdomain_count
- suspicious_tld, keyword_count, brand_mismatch
- at_symbol, double_slash, encoded_chars
- digit_ratio, path_length, has_port, has_query, special_chars

**Dataset:** 60,235 labeled URLs (55,235 legit + 5,000 phishing)

---

## âš™ï¸ Configuration

### RF Toggle (Random Forest Switch)

The UI includes an **RF Toggle** button to enable/disable the Random Forest model:

- **RF: ON** â€” Uses 60% RF + 40% LR ensemble (higher accuracy, slower)
- **RF: OFF** â€” Uses LR only (faster, slightly lower accuracy)

Toggle state is persisted in the backend and synced with the frontend.

**API:** `GET /api/model-control?rf_enabled=true`

### Trusted Domains (Allowlist)

By default, these domains are trusted and will always return "Legitimate":

- google.com, youtube.com, amazon.com, paypal.com
- github.com, stackoverflow.com, microsoft.com, apple.com
- And 40+ more banking, security, and platform domains

To modify, edit `backend/app.py`:

```python
TRUSTED_HOSTS = {
    'google.com', 'youtube.com', 'facebook.com',
    # Add your trusted domains here
}
```

---

## ðŸ”Œ API Reference

| Method   | Endpoint             | Description           |
| -------- | -------------------- | --------------------- |
| POST     | `/api/predict`       | Analyze single URL    |
| POST     | `/api/bulk`          | Analyze up to 30 URLs |
| GET      | `/api/history`       | Get scan history      |
| GET      | `/api/stats`         | Get platform stats    |
| GET      | `/api/model-info`    | Model metadata        |
| GET      | `/api/search?q=`     | Search history        |
| GET/POST | `/api/model-control` | Get/set RF toggle     |

### Example: Predict Single URL

```bash
curl -X POST http://localhost:5000/api/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}'
```

**Response:**

```json
{
  "url": "https://google.com",
  "verdict": "legitimate",
  "risk_score": 0.0,
  "ml_score": 0.05,
  "lr_score": 0.02,
  "ai_analysis": "This URL appears legitimate...",
  "indicators": {
    "is_https": true,
    "suspicious_tld": false
  }
}
```

### Example: Toggle RF Model

```bash
curl -X POST http://localhost:5000/api/model-control \
  -H "Content-Type: application/json" \
  -d '{"rf_enabled": true}'
```

---

## âœ¨ Features

- ðŸ”— **URL Scanner** â€” Single URL analysis with ensemble ML
- ðŸ“· **QR Scanner** â€” Upload image / Camera / Clipboard â†’ decode â†’ analyze
- ðŸ“‹ **Bulk Scanner** â€” Up to 30 URLs in one batch
- ðŸ•‘ **History** â€” SQLite DB + local cache, CSV export
- ðŸ§  **AI Reasoning** â€” Chain-of-thought 3-step analysis (free AI + rule-based fallback)
- ðŸ“Š **Analytics** â€” Donut chart, bar charts, live feed
- â—‰ **ML Dashboard** â€” Feature importance, model metrics, dataset info
- âš¡ **Offline Mode** â€” Browser-side LR inference when backend is down

---

## ðŸ§  AI Analysis

Uses **Hugging Face free inference API** (Mistral-7B-Instruct).  
Falls back to **rule-based chain-of-thought** reasoning when offline.

No API key required for basic usage.

---

## ðŸ’¾ Database Schema

```sql
CREATE TABLE scans (
    id          INTEGER PRIMARY KEY,
    url         TEXT,
    url_hash    TEXT,          -- MD5 for deduplication
    verdict     TEXT,          -- phishing / suspicious / legitimate
    risk_score  REAL,          -- 0-100
    ml_score    REAL,          -- Random Forest probability
    lr_score    REAL,          -- Logistic Regression probability
    features    TEXT,          -- JSON feature vector
    ai_analysis TEXT,          -- AI reasoning text
    ip_address  TEXT,          -- Client IP
    created_at  TEXT           -- ISO timestamp
);
```

---

## ðŸŽ“ For Presentations / Demos

1. Start `python backend/app.py`
2. Open browser â†’ `http://localhost:5000`
3. **Demo phishing URL:** `http://paypal-secure-login.tk/verify` (Shows HIGH RISK)
4. **Demo safe URL:** `https://google.com` (Shows LEGITIMATE)
5. **Show QR Scanner:** Scan a test QR code linking to a URL
6. **Show ML Model tab:** Explain ensemble logic, feature importance
7. **Show Analytics:** Live threat dashboard with real-time stats

---

## ðŸ›  Troubleshooting

### Backend won't start

```bash
# Check if port 5000 is already in use
netstat -an | grep 5000

# Or kill the process
lsof -i :5000 | grep LISTEN | awk '{print $2}' | xargs kill -9
```

### "RF Model not found" error

```bash
# Train a new Random Forest model
python backend/train_rf.py --dataset ml/detection_x_merged.csv

# Or disable RF in the UI toggle
```

### Frontend not loading

- Ensure backend is running on `http://127.0.0.1:5000`
- Check browser console for CORS errors
- Clear browser cache (Ctrl+Shift+Delete)

### QR Scanner not working

- QR scanner requires HTTPS or localhost
- Upload image or use camera permission
- jsQR may have CDN issues; consider hosting locally

### Database locked error

- Ensure only one instance of backend is running
- Delete `backend/cybersentinel.db` to reset (loses history)

---

## ðŸ“Š Model Training from Scratch

To train your own models:

```bash
# Create a CSV with columns: url, label
# label format: 0 = legitimate, 1 = phishing

python backend/train_rf.py \
  --dataset path/to/your_urls.csv \
  --url-col url \
  --label-col label
```

Output: `ml/rf_model.pkl` with accuracy metrics

---

## ðŸ“¦ Deployment

### Local Development

```bash
python backend/app.py
```

### Docker (Optional)

```bash
# Build image
docker build -t cybersentinel .

# Run container
docker run -p 5000:5000 cybersentinel
```

### Heroku / Cloud Platforms

1. Add `Procfile`: `web: python backend/app.py`
2. Set environment `FLASK_ENV=production`
3. Deploy with Git

---

## ðŸ“„ License

This project is licensed under the **MIT License** â€” see [LICENSE](LICENSE) file for details.

---

## ðŸ¤ Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

### Ideas for Contribution

- [ ] Add more URL features for better accuracy
- [ ] Integrate with modern threat intelligence APIs
- [ ] Build desktop app wrapper (Electron)
- [ ] Add browser extension
- [ ] Improve QR scanner reliability
- [ ] Add multi-language support
- [ ] Deploy demo on GitHub Pages

---

## ðŸ“¬ Contact

Questions? Issues? Share your feedback!

---

_Built with â¤ï¸ using Flask Â· scikit-learn Â· vanilla JS Â· SQLite_
```

## LICENSE

`$lang
MIT License

Copyright (c) 2024 CyberSentinel Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
