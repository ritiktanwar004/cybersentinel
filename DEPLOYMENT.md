# GitHub Deployment Guide

## Step 1: Create GitHub Repository

1. Go to [github.com/new](https://github.com/new)
2. Enter repository name: `cybersentinel`
3. Description: "Phishing Detection Platform with ML Ensemble & AI Analysis"
4. Choose **Public** (for portfolio) or **Private**
5. **DO NOT check** "Initialize with README" (you already have one)
6. Click **Create repository**

## Step 2: Initialize Git Locally

In your project directory, run:

```bash
cd cybersentinel
git init
git add .
git commit -m "Initial CyberSentinel commit - ML phishing detector with 97% accuracy"
```

## Step 3: Add Remote and Push

Replace `yourusername` with your actual GitHub username:

```bash
git branch -M main
git remote add origin https://github.com/yourusername/cybersentinel.git
git push -u origin main
```

If you get a **permission error**, use SSH instead:

```bash
# Generate SSH key (if you don't have one)
ssh-keygen -t ed25519 -C "your_email@example.com"

# Add SSH key to GitHub: Settings → SSH and GPG keys → New SSH key

# Then push using SSH
git remote remove origin
git remote add origin git@github.com:yourusername/cybersentinel.git
git push -u origin main
```

## Step 4: Verify Upload

Visit `https://github.com/yourusername/cybersentinel`
- ✅ Files appear
- ✅ README.md displays
- ✅ .gitignore working (ml/*.pkl not uploaded)

## Step 5: Optional - Add GitHub Topics

On your repo page:
1. Click **⚙️ Settings**
2. Scroll to **Topics**
3. Add: `phishing-detection` `machine-learning` `security` `flask` `scikit-learn`

## Step 6: Optional - Enable GitHub Pages (for documentation)

1. Settings → Pages
2. Source: `main` branch / `root` folder
3. Wait for deployment (shows green checkmark)
4. Visit `https://yourusername.github.io/cybersentinel`

## Step 7: Add Code of Conduct (Optional)

```bash
# GitHub can auto-generate one
# Go to Settings → Community → Code of Conduct → Add
```

## Updating Repository

After making changes locally:

```bash
git add .
git commit -m "Describe your changes"
git push origin main
```

---

## Quick Reference

```bash
# First time setup
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/yourusername/cybersentinel.git
git push -u origin main

# Future updates
git add .
git commit -m "Your message"
git push origin main
```

---

## Important Notes

- **Large files excluded:** `.gitignore` prevents uploading `ml/*.pkl` and `*.db` (regenerate on install)
- **Security:** Never commit API keys or credentials
- **CI/CD:** `.github/workflows/python-tests.yml` runs automatically on push
- **Dataset:** `ml/detection_x_merged.csv` is gitignored; users can train from scratch or download from releases

---

For more help, see [GitHub Docs](https://docs.github.com/en/repositories/creating-and-managing-repositories/quickstart-for-repositories).
