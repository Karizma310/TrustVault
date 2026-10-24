FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd --system trustvault \
    && useradd --system --gid trustvault --home-dir /app trustvault \
    && mkdir -p /app/private_uploads \
    && chown trustvault:trustvault /app/private_uploads

COPY --chown=trustvault:trustvault app ./app
COPY --chown=trustvault:trustvault scripts ./scripts

USER trustvault
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
