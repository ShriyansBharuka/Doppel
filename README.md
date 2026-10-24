# Doppel

> *"Its credentials are valid. But is it still itself?"*

Doppel is a security gateway for autonomous AI agents, built for the D3COY 2026 hackathon (Problem Statement: *Identity Drift Detection in Autonomous AI Agents*).

*Note: Work in progress.*

---

## Backend Run Commands (PowerShell)

```powershell
cd backend
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python -m app.contracts.sign
pytest -q
uvicorn app.main:app --reload --port 8000
```

---

## Deploy to Production

1. **Generate Secrets**:
   Generate strong secrets for both Doppel signing and JWT issuance:
   ```bash
   openssl rand -hex 32  # For DOPPEL_SECRET
   openssl rand -hex 32  # For JWT_SECRET
   ```
2. **Local Configuration**:
   Place both values in `backend/.env` along with your `GEMINI_API_KEY`:
   ```dotenv
   DOPPEL_ENV=prod
   DOPPEL_SECRET=<generated_doppel_secret>
   JWT_SECRET=<generated_jwt_secret>
   GEMINI_API_KEY=<your_gemini_api_key>
   GEMINI_MODEL=gemini-3.8-flash
   CORS_ORIGINS=http://localhost:5173,https://your-frontend-deployment.vercel.app
   ```
3. **Re-sign Role Contracts**:
   Cryptographic signatures on contracts are keyed by `DOPPEL_SECRET`. Whenever secrets change, re-sign:
   ```bash
   python -m app.contracts.sign
   ```
4. **Render Cloud Deployment**:
   - Use the included root [render.yaml](file:///e:/Projects/Decoy%20Djs%20round%200/render.yaml) blueprint.
   - Configure the identical `DOPPEL_SECRET` and `JWT_SECRET` values in your Render service environment settings.
   - The server verifies contracts on boot and strictly refuses to start in `DOPPEL_ENV=prod` if either secret is missing or unset.
5. **Keepalive Ping**:
   Configure `DOPPEL_HEALTH_URL` as a GitHub repository secret. The [.github/workflows/keepalive.yml](file:///e:/Projects/Decoy%20Djs%20round%200/.github/workflows/keepalive.yml) workflow will periodically ping `/health` every 10 minutes to prevent cold starts.

---

## Live Gemini Recording and Replay

Doppel features live agent interaction via Google Gemini function calling with intent canary (Sigil) protection:

- **Run Live Agent**:
  ```bash
  python -m app.agents.run_live --agent procurement-agent
  ```
- **Record Transcript**:
  ```bash
  python -m app.agents.run_live --agent procurement-agent --record
  ```
  Saves a sanitized JSON transcript into `app/scenarios/recordings/` which is subsequently exposed and deterministically replayed via Scenario **S1L** on the hosted console demo.

> [!NOTE]
> Modern LLMs have strong safety alignment and sometimes resist indirect prompt injections on a given run. It is completely normal to run the live agent a few times to record a session where the injection succeeds. Never manually tamper with or edit recording JSON files.

