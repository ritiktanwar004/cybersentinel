# Render Deployment Guide

This project is configured for Render using `render.yaml`.

## Prerequisites

1. Code pushed to GitHub
2. Render account connected with GitHub

## Deployment (Blueprint - Recommended)

1. Open Render dashboard
2. Click **New +** → **Blueprint**
3. Select your `cybersentinel` repository
4. Render auto-detects `render.yaml`
5. Click **Apply**

Render will automatically use:

- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn backend.app:app --bind 0.0.0.0:$PORT`
- Health check: `/api`

## Included Configuration

- `render.yaml` at repo root
- `backend/__init__.py` for stable module import path (`backend.app:app`)
- `gunicorn` dependency in `requirements.txt`

## After Deploy

1. Open your Render service URL
2. Check API health: `https://<your-service>.onrender.com/api`
3. App UI should open at root path: `https://<your-service>.onrender.com/`

## Updating Deployment

Every push to `main` triggers auto-deploy (because `autoDeploy: true`).

```bash
git add .
git commit -m "Your update"
git push origin main
```

## Troubleshooting

1. **Build fails**: confirm `requirements.txt` is valid and committed.
2. **Start fails**: verify service logs and ensure `backend/app.py` contains `app = Flask(...)`.
3. **404 at root**: verify `frontend/index.html` exists in repo.
4. **Model file missing**: if `ml/rf_model.pkl` is not in repo, app will run in LR-only mode.
