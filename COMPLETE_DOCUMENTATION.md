# 🛡 CyberSentinel - Complete Documentation & Explanation Guide

---

## 📖 Table of Contents

1. [Project Overview](#project-overview)
2. [What is Phishing?](#what-is-phishing)
3. [How CyberSentinel Works](#how-cybersentinel-works)
4. [Technologies Used](#technologies-used)
5. [Architecture Explained](#architecture-explained)
6. [Machine Learning (ML) Explained](#machine-learning-explained)
7. [Feature Extraction](#feature-extraction)
8. [Backend API](#backend-api)
9. [Frontend (Website)](#frontend-website)
10. [Database](#database)
11. [Complete Flow: From URL to Result](#complete-flow)
12. [Code Breakdown](#code-breakdown)
13. [Running the Project](#running-the-project)

---

## 1. Project Overview

### What is CyberSentinel?

CyberSentinel is a **Phishing Detection Platform** that uses Artificial Intelligence (Machine Learning) to detect whether a URL (link) is:
- 🟢 **Legitimate** (Safe website)
- 🟡 **Suspicious** (Might be dangerous)
- 🔴 **Phishing** (Definitely dangerous - trying to steal your data)

### Why Do We Need It?

Phishing is a cyber attack where hackers create fake websites that look like real ones (like fake Gmail, PayPal, Bank websites) to trick people into entering their passwords and personal information.

**Example of phishing:**
- Real: `https://www.google.com`
- Fake (Phishing): `https://www-google.com-verify.tk` (looks similar but is different)

CyberSentinel automatically checks URLs and tells you if they're dangerous!

### Project Statistics

- **Accuracy**: 97.1% (very accurate)
- **Dataset**: 60,235 URLs (trained on 60k+ real and fake URLs)
- **Features Analyzed**: 18 different characteristics of each URL
- **Models Used**: 2 AI models working together (Ensemble method)

---

## 2. What is Phishing?

### Common Phishing Tactics

| Tactic | Example | How to Spot |
|--------|---------|------------|
| **Domain Spoofing** | `paypa1.com` instead of `paypal.com` | Look for slight misspellings (1 vs l) |
| **Suspicious TLD** | `google.com.tk` | Unusual domain extensions (.tk, .xyz, .ml) |
| **Brand Impersonation** | `apple-id-verify.xyz/verify` | Real brand names in fake URLs |
| **IP Address** | `http://192.168.1.1/login` | Uses IP instead of domain name |
| **Many Hyphens** | `secure-login-verify-account-bank.com` | Too many hyphens is suspicious |
| **Encoded Characters** | `%20` in URL | URL encoding used to hide malicious intent |

### Red Flags CyberSentinel Detects

1. **No HTTPS** - Legitimate sites use `https://`, phishing often uses `http://`
2. **Suspicious Keywords** - "verify", "confirm", "urgent", "secure" used to create urgency
3. **Misspelled Domains** - Similar to real brands but slightly different
4. **Short URLs** - `bit.ly/xyz` hiding the real destination
5. **Many Subdomains** - `a.b.c.d.example.com` is unusual

---

## 3. How CyberSentinel Works

### Simple Overview

```
User enters URL
    ↓
System analyzes URL
    ↓
Machine Learning models check 18 features
    ↓
Results combined (Ensemble)
    ↓
Risk Score (0-100%)
    ↓
Verdict: Phishing / Suspicious / Legitimate
    ↓
AI explains why
```

### The Complete Process

1. **User Input**: You paste a URL into the web interface
2. **Validation**: System checks if it's a valid URL format
3. **Feature Extraction**: 18 characteristics are calculated
4. **ML Prediction**: Two AI models analyze the features
5. **Ensemble Scoring**: Results combined using weighted average (60% RF + 40% LR)
6. **Decision Making**: 
   - Score >= 60% → Phishing
   - Score 30-60% → Suspicious
   - Score < 30% → Legitimate
7. **AI Analysis**: Explains which factors made it dangerous
8. **Storage**: Result saved in database for history
9. **Display**: Result shown to user with indicators

---

## 4. Technologies Used

### Backend (Server-Side)

| Technology | Purpose | Why? |
|------------|---------|------|
| **Python 3.10+** | Programming Language | Easy to learn, great for ML |
| **Flask** | Web Framework | Lightweight, perfect for APIs |
| **SQLite** | Database | No setup needed, stores history |
| **scikit-learn** | ML Library | Pre-built ML models and tools |
| **joblib** | Model Storage | Save/load trained ML models |
| **NumPy** | Math Library | Fast numerical computations |

### Frontend (Website)

| Technology | Purpose | Why? |
|------------|---------|------|
| **HTML** | Page Structure | Defines layout |
| **CSS** | Styling/Design | Makes it look good |
| **JavaScript** | Interactivity | Makes buttons work, handles clicks |

### Deployment

| Technology | Purpose |
|------------|---------|
| **GitHub** | Code storage & version control |
| **Render** | Hosting (keeps server running 24/7) |
| **Gunicorn** | Production server (handles traffic) |

### Tools & Libraries (Used in Code)

```python
import json           # Handle JSON data
import re            # Pattern matching (regex)
import sqlite3       # Database
import hashlib       # Encryption/hashing
from urllib.parse import urlparse  # Parse URLs
from flask import Flask  # Web server
from datetime import datetime  # Time management
```

---

## 5. Architecture Explained

### System Design

```
┌─────────────────────────────────────────────────────────┐
│                   User's Browser                         │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Frontend Website (HTML/CSS/JavaScript)           │  │
│  │  - Input field for URL                            │  │
│  │  - Display results with risk score                │  │
│  │  - Show scan history                              │  │
│  └────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                           ↕ (HTTP Requests)
┌─────────────────────────────────────────────────────────┐
│                   Backend Server                         │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Flask Web Server (Python)                        │  │
│  │  - Receives URL from frontend                     │  │
│  │  - Validates URL format                           │  │
│  │  - Extracts 18 features                           │  │
│  └────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────┐  │
│  │  ML Models                                        │  │
│  │  - Logistic Regression (LR): 91.7% accurate      │  │
│  │  - Random Forest (RF): 97.1% accurate            │  │
│  │  - Ensemble: Combine both (60% RF + 40% LR)      │  │
│  └────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────┐  │
│  │  SQLite Database                                  │  │
│  │  - Store all scan results                         │  │
│  │  - Keep history of analyzed URLs                  │  │
│  │  - Calculate statistics                           │  │
│  └────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Data Flow

```
1. Frontend → URL → Backend
2. Backend → Validate & Extract Features
3. Feature Vector → ML Models
4. Model 1 (RF): Prediction 1
   Model 2 (LR): Prediction 2
5. Predictions → Ensemble (Average)
6. Result → Database
7. Backend → JSON Response → Frontend
8. Frontend → Display to User
```

---

## 6. Machine Learning (ML) Explained

### What is Machine Learning?

Machine Learning is teaching a computer to learn from examples instead of programming it manually.

**Example:**
- **Manual Way**: Program every phishing rule manually → Never complete, too many cases
- **ML Way**: Show AI 60,000 URL examples (phishing + legitimate) → AI learns patterns automatically

### The Two Models Used

#### 1. **Logistic Regression (LR)**

**What is it?**
- Simplest ML algorithm
- Draws a line to separate phishing from legitimate URLs in a "feature space"
- Uses math: `probability = 1 / (1 + e^(-x))`

**Pros:**
- ✅ Fast (instant results)
- ✅ Explainable (can understand why it decided)
- ✅ Works in browser (small model)

**Cons:**
- ❌ Less accurate (91.7%)
- ❌ Can miss complex patterns

**How it works:**
```
Features (18 numbers) → Formula → Probability (0-1) → Decision
```

#### 2. **Random Forest (RF)**

**What is it?**
- Combines 100 "decision trees" (like 100 different experts voting)
- Each tree makes a simple yes/no decision
- Final answer = majority vote

**Pros:**
- ✅ Very accurate (97.1%)
- ✅ Catches complex patterns
- ✅ Handles edge cases well

**Cons:**
- ❌ Slower (takes milliseconds)
- ❌ Larger file size
- ❌ Harder to explain

**How it works:**
```
Features → 100 Decision Trees (each votes)
Tree 1 says: 75% chance phishing
Tree 2 says: 80% chance phishing
Tree 3 says: 72% chance phishing
...
Final: Average all votes = 77% phishing
```

### Ensemble Method (The Secret Sauce)

**What is Ensemble?**
Combining multiple models to get better results than any single model alone.

**How CyberSentinel Does It:**
```
RF Prediction: 80% chance it's phishing
LR Prediction: 75% chance it's phishing

Final Score = 0.6 × 80 + 0.4 × 75 = 48 + 30 = 78%
```

**Why?**
- RF is strong but slower
- LR is fast but less accurate
- Together: Best of both worlds

---

## 7. Feature Extraction

### What are Features?

Features are characteristics of a URL that we measure. The model uses these to make a decision.

**Think of it like diagnosing a disease:**
- Doctor checks: temperature, blood pressure, cough, etc.
- Each check = 1 feature
- All features together → Diagnosis

### 18 Features CyberSentinel Checks

| # | Feature | Example | How It Works |
|---|---------|---------|------------|
| 1 | **is_https** | `https://` | Phishing often uses `http://` |
| 2 | **url_length** | `len(url) = 45` | Very long URLs = suspicious |
| 3 | **domain_length** | `len("google.com") = 10` | Too long domain = suspicious |
| 4 | **is_ip** | `192.168.1.1` | Using IP instead of domain = very suspicious |
| 5 | **hyphen_count** | `google-account-verify.com` has 2 hyphens | Too many hyphens = phishing |
| 6 | **dot_count** | `sub.domain.example.com` has 3 dots | Counts subdomains |
| 7 | **subdomain_count** | `a.b.example.com` = 2 subdomains | Many subdomains = suspicious |
| 8 | **suspicious_tld** | `.tk`, `.ml`, `.xyz` | High-abuse domain extensions |
| 9 | **keyword_count** | "login", "verify", "secure" | Phishing keywords count |
| 10 | **brand_mismatch** | `google` in URL but domain is `gmail.com` | Brand spoofing detection |
| 11 | **at_symbol** | `user@domain.com` | `@` symbol used in URL = phishing |
| 12 | **double_slash** | `//` in path section | Extra slashes = suspicious |
| 13 | **encoded_chars** | `%20` (space), `%2F` (/) | URL encoding used to hide malice |
| 14 | **digit_ratio** | `g00gle.com` (0s instead of O) | High numbers in domain = phishing |
| 15 | **path_length** | Length of `/path/to/page` | Long paths = unusual |
| 16 | **has_port** | `example.com:8080` | Custom ports = suspicious |
| 17 | **has_query** | `?param=value` | Query strings = common in phishing |
| 18 | **special_chars** | `!`, `$`, `&` | Special characters = suspicious |

### Feature Extraction Code Flow

```python
Input: "http://google-account-verify.tk/login?user=admin"

Step 1: Parse URL
  domain = "google-account-verify.tk"
  path = "/login"
  
Step 2: Extract Features
  is_https = 0 (uses http, not https)
  hyphen_count = 2 (google-account-verify has 2 hyphens)
  suspicious_tld = 1 (ends with .tk which is high-abuse)
  keyword_count = 2 ("google", "verify" are phishing keywords)
  
Step 3: Normalize Features (make them 0-1)
  Features = [0, 0.35, 0.28, 1, 0.2, 0.35, 0.08, 1, 0.2, ...]
  
Step 4: Send to ML Models
  RF Model → 85% phishing
  LR Model → 80% phishing
  
Step 5: Ensemble
  Final = 0.6×85 + 0.4×80 = 83% PHISHING
```

---

## 8. Backend API

### What is an API?

API = Application Programming Interface

It's a way for the frontend (website) to talk to the backend (server) using HTTP requests.

**Simple Analogy:**
- You're at a restaurant
- Frontend = Customer
- Backend = Kitchen
- API = Waiter (takes order, brings food)

### Main Endpoints

#### 1. **POST /api/predict** (Single URL Scan)

**Request:**
```json
{
  "url": "https://google.com"
}
```

**Response:**
```json
{
  "url": "https://google.com",
  "verdict": "legitimate",
  "risk_score": 15.5,
  "ml_score": 12.0,
  "lr_score": 18.0,
  "ai_analysis": "This URL appears legitimate...",
  "domain": "google.com",
  "timestamp": "2024-05-05T10:30:00"
}
```

**What happens:**
1. Frontend sends URL to backend
2. Backend validates the URL
3. Extracts 18 features
4. Runs through ML models
5. Calculates risk score
6. Generates AI explanation
7. Saves to database
8. Sends result back to frontend

#### 2. **POST /api/bulk** (Multiple URLs)

**Request:**
```json
{
  "urls": [
    "https://google.com",
    "http://phishing-site.tk",
    "https://github.com"
  ]
}
```

**Response:**
```json
{
  "results": [
    {"url": "https://google.com", "verdict": "legitimate", "risk_score": 15.5},
    {"url": "http://phishing-site.tk", "verdict": "phishing", "risk_score": 92.0},
    {"url": "https://github.com", "verdict": "legitimate", "risk_score": 8.0}
  ],
  "count": 3,
  "invalid": []
}
```

#### 3. **GET /api/history** (Scan History)

**Request:**
```
/api/history?limit=50&offset=0
```

**Response:**
```json
{
  "history": [
    {
      "id": 1,
      "url": "https://google.com",
      "verdict": "legitimate",
      "risk_score": 15.5,
      "created_at": "2024-05-05T10:30:00"
    },
    ...
  ],
  "limit": 50,
  "offset": 0
}
```

#### 4. **GET /api/stats** (Overall Statistics)

**Response:**
```json
{
  "total_scans": 150,
  "phishing_found": 45,
  "safe_found": 95,
  "suspicious_found": 10,
  "distribution": {
    "phishing": 45,
    "legitimate": 95,
    "suspicious": 10
  },
  "last_24h": 23,
  "lr_accuracy": 0.9173,
  "rf_accuracy": 0.9713,
  "rf_available": true,
  "rf_enabled": true
}
```

#### 5. **GET /api/model-info** (Model Details)

**Response:**
```json
{
  "models": [
    {"name": "Logistic Regression", "accuracy": 0.9173, "f1": 0.8956},
    {"name": "Random Forest", "accuracy": 0.9713, "f1": 0.9521}
  ],
  "feature_count": 18,
  "features": ["is_https", "url_length", ...],
  "dataset": "60,235 URLs",
  "ensemble": "RF(60%) + LR(40%)"
}
```

---

## 9. Frontend (Website)

### What User Sees

The website has 4 main pages:

#### 1. **Scanner Page**
- Input field to paste a URL
- Click "SCAN" button
- See result: Risk score, verdict, indicators, AI explanation

#### 2. **Bulk Scanner**
- Paste multiple URLs (one per line)
- Scan up to 30 at once
- See all results in a table

#### 3. **History**
- View all previous scans
- Search/filter by verdict
- Export to CSV

#### 4. **Model Info**
- Technical details about the ML models
- Accuracy percentages
- Feature list

### How Frontend Works

**Step-by-step:**

```javascript
1. User opens http://localhost:5000
   → Browser loads HTML/CSS/JavaScript

2. User pastes URL in input box
   → JavaScript stores it in memory

3. User clicks "SCAN" button
   → JavaScript sends HTTP request to /api/predict
   → Shows loading spinner

4. Backend responds with result
   → JavaScript receives JSON

5. JavaScript displays result
   → Shows verdict badge (phishing/safe/suspicious)
   → Shows risk score (0-100%)
   → Shows AI explanation
   → Updates statistics

6. Result also saved in database
   → Next time user opens history, they see it
```

### Frontend Technologies Explained

**HTML** - The Structure
```html
<input type="text" id="urlInput" />
<!-- This creates a text box where you type -->

<button onclick="scanUrl()">SCAN</button>
<!-- This creates a button that runs scanUrl() when clicked -->

<div id="results"></div>
<!-- This is where results appear -->
```

**CSS** - The Design
```css
button {
  background: #00d2ff;  /* Cyan color */
  padding: 12px 24px;   /* Space inside button */
  border-radius: 8px;   /* Rounded corners */
}
/* Makes buttons look nice */
```

**JavaScript** - The Logic
```javascript
async function scanUrl() {
  const url = document.getElementById("urlInput").value;
  
  // Send to backend
  const response = await fetch("/api/predict", {
    method: "POST",
    body: JSON.stringify({ url: url })
  });
  
  // Get result
  const data = await response.json();
  
  // Display result
  document.getElementById("results").innerHTML = 
    `Risk: ${data.risk_score}%`;
}
```

---

## 10. Database

### What is SQLite?

SQLite is a simple database (like Excel but more powerful).

**Features:**
- ✅ No setup needed
- ✅ Single file (`cybersentinel.db`)
- ✅ Perfect for small to medium projects
- ✅ All data stored locally

### Database Tables

#### Table 1: `scans` (Store all URL scans)

| Column | Type | Purpose |
|--------|------|---------|
| `id` | INTEGER | Unique ID (1, 2, 3, ...) |
| `url` | TEXT | The URL that was scanned |
| `url_hash` | TEXT | MD5 hash for quick lookup |
| `verdict` | TEXT | Result: "phishing", "suspicious", "legitimate" |
| `risk_score` | REAL | Score: 0-100 |
| `ml_score` | REAL | Random Forest score |
| `lr_score` | REAL | Logistic Regression score |
| `features` | TEXT | All 18 features as JSON |
| `ai_analysis` | TEXT | AI explanation |
| `ip_address` | TEXT | Who scanned it |
| `created_at` | TEXT | When it was scanned |

**Example Row:**
```
id: 1
url: https://google.com
verdict: legitimate
risk_score: 15.5
created_at: 2024-05-05T10:30:00
```

#### Table 2: `stats` (Keep count)

| Column | Type | Purpose |
|--------|------|---------|
| `key` | TEXT | Stat name |
| `value` | INTEGER | Count |

**Rows:**
```
key: "total_scans", value: 150
key: "phishing_found", value: 45
key: "safe_found", value: 95
key: "suspicious_found", value: 10
```

### How Data is Stored

```python
# When user scans a URL:

1. Extract features
2. Run ML models
3. Calculate risk score

4. Insert into database:
   INSERT INTO scans (url, verdict, risk_score, ...)
   VALUES ('https://google.com', 'legitimate', 15.5, ...)

5. Update statistics:
   UPDATE stats SET value = value + 1 WHERE key = 'total_scans'
   UPDATE stats SET value = value + 1 WHERE key = 'legitimate_found'

6. Now:
   - History page shows it
   - Statistics updated
   - Data persists even after restart
```

---

## 11. Complete Flow: From URL to Result

### Real Example: User Scans `http://paypal-verify.tk/login`

**Timeline:**

```
⏰ 10:30:00 - User opens website
   Browser loads HTML/CSS/JavaScript

⏰ 10:30:15 - User enters URL
   URL: "http://paypal-verify.tk/login"
   Stored in JavaScript variable

⏰ 10:30:16 - User clicks SCAN
   JavaScript runs: scanUrl()
   Creates HTTP POST request
   Sends URL to backend

⏰ 10:30:17 - Backend receives request
   Flask catches the request
   
⏰ 10:30:18 - Validation
   Check if URL format is valid
   Result: ✅ Valid

⏰ 10:30:19 - Feature Extraction
   Parse URL:
     domain: "paypal-verify.tk"
     path: "/login"
   
   Calculate features:
     is_https: 0 (uses http)
     hyphen_count: 1 (paypal-verify)
     suspicious_tld: 1 (uses .tk)
     keyword_count: 2 ("paypal", "verify", "login")
     brand_mismatch: 1 (paypal mentioned but not owner)
   
   All 18 features calculated

⏰ 10:30:20 - ML Prediction
   Logistic Regression:
     Formula: 1 / (1 + e^(-2.5)) = 0.924 = 92.4%
   
   Random Forest:
     Tree 1 vote: 95% phishing
     Tree 2 vote: 90% phishing
     ... (100 trees)
     Average: 93.0%
   
   Ensemble Result:
     0.6 × 93.0 + 0.4 × 92.4 = 92.76%

⏰ 10:30:21 - Decision Making
   Risk Score: 92.76%
   Is >= 60? Yes
   Verdict: 🔴 PHISHING

⏰ 10:30:22 - AI Analysis Generation
   System analyzes findings:
   - "Uses http:// instead of https://"
   - "Domain ends with .tk (high-risk TLD)"
   - "Contains 'paypal' but owned by attacker"
   - "Contains phishing keywords: verify, login"
   
   Result: "HIGH THREAT: This URL is likely a phishing "
           "attempt impersonating PayPal..."

⏰ 10:30:23 - Database Storage
   INSERT INTO scans:
     url: "http://paypal-verify.tk/login"
     verdict: "phishing"
     risk_score: 92.76
     ai_analysis: "HIGH THREAT..."
     created_at: "2024-05-05T10:30:23"
   
   UPDATE stats:
     phishing_found: 45 → 46

⏰ 10:30:24 - Response Sent
   Backend sends JSON to frontend:
   {
     "verdict": "phishing",
     "risk_score": 92.76,
     "ml_score": 93.0,
     "lr_score": 92.4,
     "ai_analysis": "HIGH THREAT..."
   }

⏰ 10:30:25 - Frontend Display
   JavaScript receives response
   Updates page with:
   ✗ RED badge: "PHISHING"
   📊 Risk Score: 92.76%
   🧠 AI explanation
   📊 Stats updated

⏰ 10:30:26 - User Sees Result
   🎉 User warns about phishing!
```

---

## 12. Code Breakdown

### Core Algorithm: The Prediction

**Simplified Version:**

```python
def scan_url(url):
    # Step 1: Extract features (18 numbers)
    features = extract_features(url)  
    # Result: [0, 0.35, 0.28, 1, 0.2, ...]
    
    # Step 2: Logistic Regression prediction
    lr_score = logistic_regression_predict(features)
    # Result: 0.92 (92%)
    
    # Step 3: Random Forest prediction
    rf_score = random_forest_predict(features)
    # Result: 0.93 (93%)
    
    # Step 4: Ensemble (combine)
    final_score = 0.6 * rf_score + 0.4 * lr_score
    # Result: 0.6*0.93 + 0.4*0.92 = 0.928 (92.8%)
    
    # Step 5: Decision
    if final_score >= 0.60:
        verdict = "phishing"
    elif final_score >= 0.30:
        verdict = "suspicious"
    else:
        verdict = "legitimate"
    
    return {
        'verdict': verdict,
        'risk_score': final_score * 100,
        'ml_score': rf_score * 100,
        'lr_score': lr_score * 100
    }
```

### Feature Extraction: Detailed Code

```python
def extract_features(url):
    """Extract 18 features from URL"""
    
    # Parse the URL
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    
    features = {}
    
    # Feature 1: HTTPS or HTTP?
    features['is_https'] = 1 if url.startswith('https://') else 0
    # Result: 1 (safe) or 0 (unsafe)
    
    # Feature 2: URL Length
    features['url_length'] = min(len(url), 200) / 200
    # Scale: 0-1 (normalize)
    # Long URLs (>200) more suspicious
    
    # Feature 3: Domain Length
    features['domain_length'] = min(len(domain), 100) / 100
    # Long domain names suspicious
    
    # Feature 4: Is IP Address?
    is_ip = re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain)
    features['is_ip'] = 1 if is_ip else 0
    # IP addresses = very suspicious
    
    # Feature 5: Hyphen Count
    hyphens = domain.count('-')
    features['hyphen_count'] = min(hyphens, 10) / 10
    # Many hyphens = phishing tactic
    
    # Feature 6: Dot Count
    dots = domain.count('.')
    features['dot_count'] = min(dots, 8) / 8
    # More dots = more subdomains = suspicious
    
    # ... (repeat for all 18 features)
    
    return features
```

### Logistic Regression Math

```python
def logistic_regression_predict(features):
    """LR Formula: probability = 1 / (1 + e^(-x))"""
    
    # Normalize features
    mean = [0.42, 0.35, 0.28, ...]  # Average values
    scale = [0.49, 0.32, 0.28, ...]  # Variation
    
    normalized = []
    for i, feature in enumerate(features):
        normalized.append((feature - mean[i]) / scale[i])
    
    # Calculate logit (weighted sum)
    weights = [0.95, -0.35, -0.28, ...]  # Model learned weights
    logit = sum(w * f for w, f in zip(weights, normalized)) + intercept
    
    # Apply sigmoid function
    # This converts any number to 0-1 range
    probability = 1 / (1 + 2.718 ** (-logit))
    
    return probability  # 0.0 to 1.0
```

### Database Operations

```python
# Saving a scan
url_hash = hashlib.md5(url.encode()).hexdigest()

conn = sqlite3.connect("cybersentinel.db")
cursor = conn.cursor()

cursor.execute("""
    INSERT INTO scans 
    (url, url_hash, verdict, risk_score, created_at)
    VALUES (?, ?, ?, ?, ?)
""", (url, url_hash, "phishing", 92.76, datetime.now()))

# Update statistics
cursor.execute("""
    UPDATE stats SET value = value + 1 
    WHERE key = 'phishing_found'
""")

conn.commit()
conn.close()
```

### API Request Handler

```python
@app.route('/api/predict', methods=['POST'])
def predict_url():
    # 1. Get JSON from request
    data = request.get_json()
    url = data.get('url')
    
    # 2. Validate
    if not url:
        return {'error': 'URL required'}, 400
    
    # 3. Predict
    result = ensemble_predict(url)
    
    # 4. Save to database
    save_to_database(result)
    
    # 5. Return result as JSON
    return {
        'url': url,
        'verdict': result['verdict'],
        'risk_score': result['risk_score'],
        'ai_analysis': generate_ai_analysis(result)
    }
```

---

## 13. Running the Project

### Option 1: Run CYBERSENTINEL_COMPLETE.py (Recommended for Learning)

```bash
# 1. Navigate to project
cd c:\Users\msi-1\OneDrive\Desktop\cybersentinel

# 2. Activate virtual environment
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies (first time only)
pip install flask scikit-learn numpy pandas

# 4. Run the all-in-one file
python CYBERSENTINEL_COMPLETE.py

# 5. Open browser
# Go to: http://localhost:5000

# 6. Start scanning URLs!
```

### Option 2: Run Full Project Structure

```bash
# 1. Navigate to project
cd c:\Users\msi-1\OneDrive\Desktop\cybersentinel

# 2. Activate virtual environment
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run backend
python backend/app.py

# 5. Open browser
# Go to: http://localhost:5000
```

### What Happens When You Run

```
[ML] ✓ RF model loaded — acc=0.9713
[ML] ✓ LR weights loaded — acc=0.9173

═════════════════════════════════════
  CyberSentinel Backend — Starting Up
═════════════════════════════════════
  DB: C:\...\cybersentinel.db
  RF Model: ✓ Loaded
  LR Weights: ✓ Loaded
  API: http://localhost:5000/api/
  App: http://localhost:5000/
═════════════════════════════════════

 * Running on http://127.0.0.1:5000
```

### How to Use Once Running

1. **Open Browser**: `http://localhost:5000`
2. **See Website**: Beautiful dark interface loads
3. **Paste URL**: Enter any URL you want to check
4. **Click SCAN**: Send to backend
5. **Wait 1-2 seconds**: ML models process
6. **See Result**: Risk score, verdict, AI explanation
7. **View History**: All past scans saved
8. **Check Stats**: See how many phishing caught

---

## 📚 Quick Reference: How to Explain It to Others

### To a Non-Technical Person

"CyberSentinel is like a security guard for your internet. You give it a link, and it checks if it looks like a scam. It analyzes things like whether it uses HTTPS, if the domain looks real, if it's trying to steal your password. It gives a risk score and tells you if it's safe or dangerous."

### To a Junior Developer

"It's a Flask web app with a React-like frontend. Backend uses scikit-learn for ML - two models (LR and RF) that analyze 18 URL features. Results stored in SQLite. Frontend sends POST requests to /api/predict, gets JSON back, displays results. Uses ensemble method: 60% RF + 40% LR for final score."

### To a Tech Interviewer

"CyberSentinel uses an ensemble ML approach combining Logistic Regression (91.7% accuracy) and Random Forest (97.1% accuracy) to detect phishing URLs. It extracts 18 features from URLs, normalizes them, feeds to both models with a 60/40 weighted average. Built on Flask with SQLite persistence. Scales to 30 URLs in bulk mode. Can handle Render deployment with dynamic PORT binding."

---

## 🎯 Key Takeaways

| Concept | What It Is | Why It Matters |
|---------|-----------|----------------|
| **Phishing** | Fake websites stealing data | Common attack, needs detection |
| **Features** | Characteristics of URLs | ML models learn from them |
| **Ensemble** | Combining multiple models | Better accuracy than single model |
| **Flask** | Web framework | Handles API requests |
| **SQLite** | Simple database | Stores scan history |
| **API** | Communication protocol | Frontend talks to backend |
| **Risk Score** | 0-100% threat level | Easy for users to understand |
| **Accuracy** | 97.1% | Very reliable |

---

## 🔗 Technology Stack Summary

```
┌─────────────────────────────┐
│    USER LAYER               │
│  - Web Browser              │
│  - HTML/CSS/JavaScript      │
└────────────┬────────────────┘
             │
┌────────────▼────────────────┐
│    APPLICATION LAYER        │
│  - Flask (Python)           │
│  - API Endpoints            │
│  - Feature Extraction       │
└────────────┬────────────────┘
             │
┌────────────▼────────────────┐
│    ML LAYER                 │
│  - Logistic Regression      │
│  - Random Forest            │
│  - Ensemble Scoring         │
└────────────┬────────────────┘
             │
┌────────────▼────────────────┐
│    DATA LAYER               │
│  - SQLite Database          │
│  - Model Weights (JSON)     │
│  - Scan History             │
└─────────────────────────────┘
```

---

## ❓ FAQ

**Q: Why two ML models instead of one?**
A: Ensemble method - combines strengths. RF catches complex patterns, LR is fast. Together = best results.

**Q: How accurate is it?**
A: 97.1% on 60,235 URLs. Very accurate, but nothing is 100%.

**Q: Can it detect all phishing?**
A: Most modern phishing, yes. But new techniques might bypass it. It's a good first line of defense.

**Q: How fast does it work?**
A: URL scanning takes 50-200 milliseconds. Instant for user.

**Q: Where is data stored?**
A: Locally in SQLite database (`cybersentinel.db`). No cloud storage.

**Q: Can I use the models for my own project?**
A: Yes! The weights and model files are provided. Easy to integrate.

**Q: How do I improve accuracy?**
A: Train on more data. Need more phishing + legitimate URL examples.

---

## 🚀 Next Steps to Learn More

1. **Run the project** - See how it works firsthand
2. **Modify features** - Add/remove features, see impact
3. **Train your own model** - Use `backend/train_rf.py`
4. **Deploy to Render** - Make it live on internet
5. **Build an extension** - Browser plugin using this API

---

**Last Updated**: May 5, 2026  
**Project**: CyberSentinel v1.0  
**Accuracy**: 97.1%  
**Status**: Production Ready ✅

