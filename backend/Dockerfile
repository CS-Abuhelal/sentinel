FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY contracts/ ./contracts/
COPY ingest/ ./ingest/
COPY detection/ ./detection/
COPY agent/ ./agent/
COPY policy/ ./policy/
COPY executor/ ./executor/
COPY pipeline/ ./pipeline/
COPY backend/ ./backend/

EXPOSE 8000

CMD ["sh", "-c", "alembic -c backend/alembic.ini upgrade head && uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload"]
