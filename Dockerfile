FROM python:3.11-slim

# Install uv
RUN pip install --upgrade pip && pip install uv

WORKDIR /app

COPY . .

RUN uv pip install --system .

ENTRYPOINT ["k8s-info"]
