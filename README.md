# Blossom Web Panel

Key redemption + admin panel for Blossom loader distribution.

## Setup

```bash
# Install dependencies
pip install flask gunicorn

# Set admin password (optional, defaults to "blossom2026")
set BLOSSOM_ADMIN_PASS=your_password

# Run
python app.py
```

Panel runs on http://localhost:5000

## How It Works

### Selling Flow

1. **Generate keys** in the admin panel (or use keygen.exe for bulk)
2. **Build loaders** on your Windows PC:
   ```
   loader_gen.exe /build key=XXXXX-XXXXX-XXXXX-XXXXX type=day
   ```
3. **Upload the loader** in admin panel (paste key + upload the .exe)
4. **Customer enters key** on the redemption page
5. **Customer downloads loader** automatically

### Admin Panel

- **URL:** http://your-server:5000/admin
- **Password:** blossom2026 (set via BLOSSOM_ADMIN_PASS env var)
- Generate day/lifetime keys
- Upload loader EXEs for each key
- View all keys and accounts
- Reset HWIDs for customers

### Customer Page

- **URL:** http://your-server:5000/redeem
- Cherry blossom themed
- Enter key → download loader
- Clean, simple

### API

- `POST /api/validate` — validate a key: `{"key": "XXXXX-XXXXX-XXXXX-XXXXX"}`
- `GET /api/accounts` — list all accounts (for Discord bot)
- `DELETE /api/accounts` — delete account: `{"username": "xxx"}`
- `POST /api/accounts/reset-hwid` — reset HWID: `{"username": "xxx"}`

### Files

```
webpanel/
  app.py              — Flask server
  blossom.db          — SQLite database (auto-created)
  loaders/            — uploaded loader EXEs
  templates/
    redeem.html       — customer key redemption page
    admin.html        — admin panel
    admin_login.html  — admin login
```

## Hosting Recommendations

| Provider | Price | Best For |
|----------|-------|----------|
| **DigitalOcean** | $5/mo | Best overall, easy setup |
| **Hetzner** | ~$4/mo | Cheapest VPS, great perf |
| **Railway** | Free tier | Easiest deploy, no server mgmt |
| **Render** | Free tier | Easy but sleeps after inactivity |
| **Vultr** | $3.50/mo | Budget option |

### Easiest: Railway

1. Sign up at railway.app
2. Create new project → Deploy from GitHub repo
3. Upload the `webpanel/` folder to a GitHub repo
4. Railway auto-detects Python and deploys
5. Set env var: `BLOSSOM_ADMIN_PASS=your_password`
6. Done — you get a public URL

### Best: DigitalOcean ($5/mo)

1. Sign up at digitalocean.com
2. Create a Droplet (Ubuntu, $5/mo basic)
3. SSH in and install Python:
   ```bash
   apt update && apt install python3-pip -y
   pip3 install flask gunicorn
   ```
4. Upload the webpanel files via SCP or Git
5. Set the admin password:
   ```bash
   export BLOSSOM_ADMIN_PASS=your_password
   ```
6. Run with gunicorn:
   ```bash
   gunicorn -w 4 -b 0.0.0.0:5000 app:app
   ```
7. Optional: use nginx as reverse proxy for HTTPS

## Lovable Integration

Add a link/button on your Lovable site that goes to:
```
http://your-server/redeem
```

Or embed it in an iframe:
```html
<iframe src="http://your-server/redeem" width="500" height="500" frameborder="0"></iframe>
```
