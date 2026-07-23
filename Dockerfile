FROM python:3.12-slim

LABEL maintainer="s1d9e"
LABEL description="XecureX - Security Audit Tool"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

ENTRYPOINT ["xecurex"]
CMD ["--help"]
