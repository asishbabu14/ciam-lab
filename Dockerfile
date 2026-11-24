FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

ENV IDP_MODE=local
ENV BIND_HOST=0.0.0.0
ENV PUBLIC_HOST=127.0.0.1

EXPOSE 8000 9000 9001
CMD ["python", "-m", "ciam_lab.serve"]
