# 🚀 Deploying PhishLens PhishGuard to Vercel

PhishLens is pre-configured with a dual-tier architecture on Vercel:
- **Frontend**: Cyber Defense Dashboard & Inbox Interception Simulator served statically from `public/`.
- **Backend API**: Python Serverless Functions running Flask & the trained Machine Learning model in `api/index.py`.

---

## ⚡ Method 1: 1-Click Deploy via GitHub (Recommended)

### Step 1: Push Code to GitHub
Ensure all your files (including `vercel.json`, `api/index.py`, `public/`, and `requirements.txt`) are committed and pushed to your GitHub repository:
```bash
git add .
git commit -m "Deploy PhishLens to Vercel"
git push origin main
```

### Step 2: Import into Vercel
1. Go to **[vercel.com/new](https://vercel.com/new)** and log in.
2. Under **"Import Git Repository"**, select your `shadowlens` repository.
3. Configure the Project:
   - **Framework Preset**: `Other` (Vercel automatically detects `vercel.json`).
   - **Root Directory**: `./` (leave default).
4. *(Optional)* **Environment Variables**:
   - Add `GEMINI_API_KEY` (if you want live Gemini AI explanations). If omitted, PhishLens automatically uses its high-speed built-in neural heuristic engine.
5. Click **Deploy**.

Within 60 seconds, your application will be live at `https://your-project-name.vercel.app`!

---

## 💻 Method 2: Deploy via Vercel CLI

If you have Node.js and the Vercel CLI installed:

```bash
# 1. Install Vercel CLI (if not already installed)
npm install -g vercel

# 2. Login to your Vercel account
vercel login

# 3. Deploy to Preview
vercel

# 4. Deploy to Production
vercel --prod
```

---

## 🌐 Live Endpoints on Vercel

Once deployed, your Vercel deployment provides:

| URL Path | Type | Description |
|---|---|---|
| `https://<your-app>.vercel.app/` | Frontend | Webmail Simulator & Cyber Defense Hub |
| `https://<your-app>.vercel.app/health` | Serverless API | System Health & ML status |
| `https://<your-app>.vercel.app/api/analyze/url` | Serverless API | Deep URL & ML analysis |
| `https://<your-app>.vercel.app/api/analyze/email` | Serverless API | Sender pattern & link inspection |
| `https://<your-app>.vercel.app/api/analyze/ml` | Serverless API | Machine Learning 29-feature classifier |
| `https://<your-app>.vercel.app/api/detect/lookalike` | Serverless API | Homoglyph & typosquat generator |

---

## ⚙️ Configuration Files Overview

- **[`vercel.json`](file:///c:/Users/YASHICAA%20RS/OneDrive/Desktop/shadowlens-main/shadowlens-main/vercel.json)**: Maps `/api/*` and `/health` routes to `@vercel/python` and root requests to `@vercel/static`.
- **[`api/index.py`](file:///c:/Users/YASHICAA%20RS/OneDrive/Desktop/shadowlens-main/shadowlens-main/api/index.py)**: Python WSGI serverless entrypoint for Flask.
- **[`requirements.txt`](file:///c:/Users/YASHICAA%20RS/OneDrive/Desktop/shadowlens-main/shadowlens-main/requirements.txt)**: Lean serverless-optimized dependencies.
- **[`public/`](file:///c:/Users/YASHICAA%20RS/OneDrive/Desktop/shadowlens-main/shadowlens-main/public/)**: Static frontend assets (`index.html`, `dashboard.js`, `standalone_prototype.html`).
