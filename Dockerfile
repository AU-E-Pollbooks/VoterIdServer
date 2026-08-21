# Use an official lightweight Python image
FROM python:3.9-slim

# Install required system packages
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libtesseract-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /workspace

# Only the application code is baked into the image. Configuration, the
# voter database, and the TLS private key / certificates are supplied at
# runtime via a mounted volume (see README.md) so that no key material or
# environment-specific config ever ends up inside the image or the repo.
COPY voter_id_server.py .

# Install dependencies
RUN pip install --no-cache-dir \
    cryptography \
    opencv-python-headless \
    pandas \
    pytesseract \
    numpy \
    Pillow

# Expose the Voter ID service port (6666)
EXPOSE 6666

# Run the Voter ID server. The working directory at runtime should be the
# mounted config directory (see README.md), which is why this uses an
# absolute path to the script but relies on relative paths (config.ini,
# voter_db.csv, key/cert files) being resolved from the current directory.
CMD ["python", "/workspace/voter_id_server.py"]
