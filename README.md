# Tweeter

A modernized Tweeter social feed built with React and Flask.

## Client

```bash
cd client
npm install
npm start
```

## Server

```bash
cd server
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export JWT_SECRET_KEY="replace-this-in-production"
python app.py
```

For production, build the client with `npm run build` and serve the generated `client/build` directory through Flask or your preferred static host.

### Notes
- SQLite is used by default for local development.
- Set `DATABASE_URL` to use another SQLAlchemy-supported database.
- Set `CORS_ORIGINS` to a comma-separated list of allowed origins in production.
