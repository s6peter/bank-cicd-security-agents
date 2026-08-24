import os
from datetime import datetime, timezone

import psycopg
from flask import Flask, jsonify, request
from flask_cors import CORS

SEASONS = ["spring", "summer", "fall", "winter"]
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://voting:voting@localhost:5432/voting")

app = Flask(__name__)
CORS(app)


def connection():
    return psycopg.connect(DATABASE_URL)


def init_db():
    with connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS votes (
                id BIGSERIAL PRIMARY KEY,
                season TEXT NOT NULL CHECK (season IN ('spring', 'summer', 'fall', 'winter')),
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )


@app.before_request
def ensure_schema():
    init_db()


@app.get("/health")
def health():
    return jsonify({"status": "ok", "time": datetime.now(timezone.utc).isoformat()})


@app.get("/options")
def options():
    return jsonify({"question": "What is your favorite season?", "options": SEASONS})


@app.post("/votes")
def vote():
    body = request.get_json(silent=True) or {}
    season = str(body.get("season", "")).lower()
    if season not in SEASONS:
        return jsonify({"error": f"season must be one of: {', '.join(SEASONS)}"}), 400

    with connection() as conn:
        conn.execute("INSERT INTO votes (season) VALUES (%s)", (season,))
    return jsonify({"status": "recorded", "season": season}), 201


@app.get("/results")
def results():
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT season, COUNT(*)::int AS votes
            FROM votes
            GROUP BY season
            ORDER BY season
            """
        ).fetchall()
    totals = {season: 0 for season in SEASONS}
    totals.update({season: count for season, count in rows})
    return jsonify({"question": "What is your favorite season?", "results": totals})
