# دفتر مالی شخصی — Deployment Guide
## Stack: Node.js + Express + MongoDB Atlas + Render

---

## 📁 Project Structure

```
finance-app/
├── server.js          # Express API + JWT auth + MongoDB
├── package.json
├── render.yaml        # Render deploy config
├── .env.example       # Environment variable template
├── .gitignore
└── public/
    └── index.html     # Full frontend (RTL Dari/Persian UI)
```

---

## 🚀 Step-by-Step Deployment

### Step 1 — MongoDB Atlas (free tier)

1. Go to https://cloud.mongodb.com and sign up (free)
2. Create a new **Free Cluster** (M0 Sandbox)
3. Under **Database Access** → Add a database user (username + password)
4. Under **Network Access** → Add IP `0.0.0.0/0` (allow all — required for Render)
5. Click **Connect** → **Drivers** → copy the connection string:
   ```
   mongodb+srv://<user>:<password>@cluster0.xxxxx.mongodb.net/financeapp?retryWrites=true&w=majority
   ```

### Step 2 — GitHub

```bash
# In the finance-app/ directory:
git init
git add .
git commit -m "Initial commit"

# Create a new repo on github.com, then:
git remote add origin https://github.com/YOUR_USERNAME/finance-app.git
git branch -M main
git push -u origin main
```

### Step 3 — Render

1. Go to https://render.com and sign up (free)
2. Click **New → Web Service**
3. Connect your GitHub repo
4. Render detects `render.yaml` automatically — confirm settings:
   - **Build Command:** `npm install`
   - **Start Command:** `node server.js`
   - **Environment:** Node
5. Add Environment Variables:
   | Key | Value |
   |-----|-------|
   | `MONGO_URI` | Your Atlas connection string from Step 1 |
   | `JWT_SECRET` | Any long random string (or use Render's "Generate" button) |
6. Click **Create Web Service**
7. Wait ~2 minutes → your app is live at `https://finance-app-xxxx.onrender.com`

---

## 🔑 Default Login Credentials

| Username | Password |
|----------|----------|
| `admin`  | `1234`   |
| `کاربر`  | `1234`   |

> **Change your password immediately** after first login via Settings → User Settings.

---

## 🔒 Security Notes

- JWT tokens expire after **30 days** — users re-login automatically
- Tokens are stored **in memory only** (no localStorage/sessionStorage)
- Passwords are hashed with **bcrypt** (10 rounds)
- Each user's data is isolated in MongoDB

---

## 🛠 Local Development

```bash
# 1. Install dependencies
npm install

# 2. Create .env from template
cp .env.example .env
# Edit .env with your MONGO_URI and JWT_SECRET

# 3. Start server
npm start
# → Open http://localhost:3000
```

---

## 📡 API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/login` | ❌ | Login → returns JWT token |
| POST | `/api/auth/change` | ✅ | Change username/password |
| GET | `/api/data` | ✅ | Load user's finance data |
| PUT | `/api/data` | ✅ | Save user's finance data |
| GET | `/api/config` | ✅ | Load currency config |
| PUT | `/api/config` | ✅ | Save currency config |
