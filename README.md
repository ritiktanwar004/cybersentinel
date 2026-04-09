# 🛡 CyberSentinel — Phishing Detection Platform

[![Python](https://img.shields.io/badge/Python-3.10+-blue)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3+-green)](https://flask.palletsprojects.com)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3+-orange)](https://scikit-learn.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](#license)

> **Advanced ML + AI-powered phishing detection platform**  
> 🎓 College project · 60,235 URLs trained · **97.1% accuracy** · Ensemble ML · Chain-of-Thought AI · QR Scanner · Real-time analytics

---

## 📁 Project Structure

```
cybersentinel/
├── backend/
│   ├── app.py                  ← Flask REST API + SQLite database
│   └── cybersentinel.db        ← Auto-created on first run
├── frontend/
│   ├── index.html              ← Main app (multi-page)
│   ├── css/style.css           ← Full styling
│   └── js/app.js               ← Frontend logic + browser ML
└── ml/
    ├── model_weights.json      ← LR weights (used in browser too)
    └── rf_model.pkl            ← Random Forest model (backend)
```

---

## 🚀 Installation & Setup

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

## 🤖 ML Architecture

| Model                                   | Accuracy      | F1 Score   | Ensemble Weight |
| --------------------------------------- | ------------- | ---------- | --------------- |
| **Random Forest** (100 trees, depth=15) | **97.14%** ⭐ | **0.7986** | **60%**         |
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

## ⚙️ Configuration

### RF Toggle (Random Forest Switch)

The UI includes an **RF Toggle** button to enable/disable the Random Forest model:

- **RF: ON** — Uses 60% RF + 40% LR ensemble (higher accuracy, slower)
- **RF: OFF** — Uses LR only (faster, slightly lower accuracy)

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

## 🔌 API Reference

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

## ✨ Features

- 🔗 **URL Scanner** — Single URL analysis with ensemble ML
- 📷 **QR Scanner** — Upload image / Camera / Clipboard → decode → analyze
- 📋 **Bulk Scanner** — Up to 30 URLs in one batch
- 🕑 **History** — SQLite DB + local cache, CSV export
- 🧠 **AI Reasoning** — Chain-of-thought 3-step analysis (free AI + rule-based fallback)
- 📊 **Analytics** — Donut chart, bar charts, live feed
- ◉ **ML Dashboard** — Feature importance, model metrics, dataset info
- ⚡ **Offline Mode** — Browser-side LR inference when backend is down

---

## 🧠 AI Analysis

Uses **Hugging Face free inference API** (Mistral-7B-Instruct).  
Falls back to **rule-based chain-of-thought** reasoning when offline.

No API key required for basic usage.

---

## 💾 Database Schema

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

## 🎓 For Presentations / Demos

1. Start `python backend/app.py`
2. Open browser → `http://localhost:5000`
3. **Demo phishing URL:** `http://paypal-secure-login.tk/verify` (Shows HIGH RISK)
4. **Demo safe URL:** `https://google.com` (Shows LEGITIMATE)
5. **Show QR Scanner:** Scan a test QR code linking to a URL
6. **Show ML Model tab:** Explain ensemble logic, feature importance
7. **Show Analytics:** Live threat dashboard with real-time stats

---

## 🛠 Troubleshooting

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

## 📊 Model Training from Scratch

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

## 📦 Deployment

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

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

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

## 📬 Contact

Questions? Issues? Share your feedback!

---

_Built with ❤️ using Flask · scikit-learn · vanilla JS · SQLite_
