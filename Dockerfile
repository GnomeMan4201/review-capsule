FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements*.txt ./
RUN pip install --no-cache-dir -r requirements-hosted.txt
COPY . .
RUN useradd --uid 10001 --create-home capsule
USER capsule
CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py hosted_demo && exec gunicorn config.wsgi:application --bind 0.0.0.0:${PORT:-8000} --workers 2 --threads 2 --access-logfile - --error-logfile -"]
