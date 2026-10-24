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
