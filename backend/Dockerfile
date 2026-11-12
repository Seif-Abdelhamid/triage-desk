FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN useradd --create-home --uid 10001 app
COPY pyproject.toml ./
COPY triage_desk ./triage_desk
COPY alembic ./alembic
COPY alembic.ini ./
RUN pip install --no-cache-dir ".[scan]"
USER app
EXPOSE 8000
CMD ["uvicorn", "triage_desk.main:build_default_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
