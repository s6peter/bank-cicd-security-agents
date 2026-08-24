ARG BASE_IMAGE=public.ecr.aws/docker/library/python:3.12-slim
FROM ${BASE_IMAGE}

WORKDIR /app
COPY pyproject.toml requirements-agentcore.txt ./
COPY src ./src
COPY prompts ./prompts
COPY policies ./policies
COPY deploy ./deploy
RUN pip install --no-cache-dir -r requirements-agentcore.txt && pip install --no-cache-dir --no-deps .

USER 10001
EXPOSE 8080
CMD ["python", "deploy/agentcore_app.py"]
