ARG PYTHON_VER

FROM python:${PYTHON_VER}-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    python3-dev \
    gcc \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    build-essential \
    cargo \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip \
  && pip install poetry

WORKDIR /local
COPY . /local

RUN poetry config virtualenvs.create false \
  && poetry install --no-interaction --no-ansi