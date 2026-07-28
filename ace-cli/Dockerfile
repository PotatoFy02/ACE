FROM python:3.12-slim

WORKDIR /ace

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY schemas/ schemas/
COPY parsers/ parsers/
COPY delta_engine/ delta_engine/
COPY patch_generator/ patch_generator/
COPY cli.py .

# Entry point
ENTRYPOINT ["python", "cli.py"]
CMD ["--help"]