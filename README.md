# Voter ID Service (OCR-based)

This is an alternative implementation of the **Voter ID Service** role in the
secure pollbook architecture. It is a companion to the main
[pollbook-server](../pollbook-server) repository, which contains the
check-in server, the trusted/untrusted clients, and a "mock" Voter ID
service that does not attempt to verify identity documents. This service
implements that same role, but actually performs identity verification: it
decodes a photographed ID document, runs OCR (via Tesseract) to extract the
license number, and matches it against a voter database.

Because it plays the same protocol role as the Voter ID service in the main
repository, it is designed as a **drop-in replacement**: it uses the same
mutually-authenticated TLS setup (its certificate must be issued by the same
CA, using the `CN = Voter ID Server` identity) so that the check-in server
and clients trust it without any changes on their end.

## What it does

- Listens for TLS connections from untrusted clients.
- Receives a base64-encoded photo of a voter's ID document.
- Runs an OpenCV preprocessing pipeline (rotation, resizing, denoising,
  adaptive thresholding) followed by Tesseract OCR to extract text from the
  image.
- Matches the extracted license number against a CSV voter database.
- Returns a response containing the voter's registration/unique ID, name,
  and address, signed with the service's private key so the check-in server
  can verify it came from a legitimate Voter ID service.

## Dependencies

- Python 3.9+
- [`cryptography`](https://pypi.org/project/cryptography/) for signing responses
- [`opencv-python-headless`](https://pypi.org/project/opencv-python-headless/) and [`pytesseract`](https://pypi.org/project/pytesseract/) (plus the `tesseract-ocr` system package) for OCR
- `pandas` for reading the voter database CSV
- `Pillow` for image decoding

All of these are installed automatically by the Dockerfile.

## Configuration

Copy `config.ini.example` to `config.ini` and fill in the paths to your
key/certificate files:

```ini
[Basic]
id_service_port = 6666

[Security]
id_service_cert = id_certificate.pem
local_private_key = private_key.pem
ca_cert = ca_cert.pem
```

You'll also need:

- `voter_db.csv` — a CSV with columns `license_number,name,address`. A
  synthetic example is included in this repo for testing.
- A private key + certificate for this service (`CN = Voter ID Server`) and
  the CA certificate, generated using the `generate_keys.sh` script from the
  companion pollbook-server repository so that this service is trusted by
  the rest of the system.

None of `config.ini`, the key/cert files, or the CA are committed to this
repository (see `.gitignore`) — they must be generated locally.

## Building and running with Docker

Build the image (from this directory, containing the `Dockerfile` and
`voter_id_server.py`):

```
docker build -t voter_id_server_image .
```

Run the container, mounting a directory that contains `config.ini`,
`voter_db.csv`, and your generated key/cert files as `/app`:

```
docker run -d --name voter_id_server \
  -p 6667:6666 \
  -v "<path-to-your-config-directory>:/app" \
  -w /app \
  voter_id_server_image python /workspace/voter_id_server.py
```

Replace `<path-to-your-config-directory>` with the path to a local folder
containing `config.ini`, `voter_db.csv`, and the key/cert files described
above (for example, the `server1/` directory produced by the companion
repository's local test deployment, if you're running this service as a
substitute for its mock Voter ID service).

Check that it started correctly:

```
docker logs voter_id_server
```

Open a shell inside the running container for debugging:

```
docker exec -it voter_id_server /bin/bash
```

## Status

