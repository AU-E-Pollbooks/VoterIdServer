import asyncio
import json
import ssl
import logging
import configparser
import base64
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key


class VoterIDService:
    def __init__(self, config):
        self.logger = logging.getLogger("voter_id_service")
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

        self.server_cert = config["Security"]["id_service_cert"]
        self.server_key = config["Security"]["local_private_key"]
        self.ca_cert = config["Security"]["ca_cert"]
        self.host = "0.0.0.0"
        self.port = int(config["Basic"]["id_service_port"])

        with open(self.server_key, "rb") as key_file:
            self.private_key_signer = load_pem_private_key(
                key_file.read(), password=None)

    def create_ssl_context(self):
        ssl_context = ssl.create_default_context(
            ssl.Purpose.CLIENT_AUTH, cafile=self.ca_cert)
        ssl_context.load_cert_chain(
            certfile=self.server_cert, keyfile=self.server_key)
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        ssl_context.check_hostname = False
        return ssl_context

    async def handle_client(self, reader, writer):
        try:
            size_data = await reader.readline()
            size_data = size_data.strip()

            if not size_data:
                self.logger.error(
                    "❌ Received empty message size, client might have disconnected early.")
                return

            try:
                message_size = int(size_data)
                if message_size <= 0:
                    self.logger.error(
                        f"❌ Invalid message size received: {message_size}")
                    return
            except ValueError:
                self.logger.error(
                    f"❌ Message size is not an integer: {size_data}")
                return

            try:
                message = await asyncio.wait_for(reader.readexactly(message_size), timeout=5)
                message = message.decode().strip()
            except asyncio.TimeoutError:
                self.logger.error(
                    f"❌ Timeout waiting for full message (size: {message_size}).")
                return
            except asyncio.IncompleteReadError as e:
                self.logger.error(f"❌ Incomplete message received: {str(e)}")
                return

            self.logger.info(f"✅ Received request.")

            try:
                request_json = json.loads(message)
            except json.JSONDecodeError as e:
                self.logger.error(f"❌ JSON Decode Error: {e}.")
                return

            response = self.process_request(request_json)

            response_string = json.dumps(
                response, separators=(",", ":")) + "\n"
            writer.write(response_string.encode())
            await writer.drain()

            self.logger.info(f"✅ Sent response.")

            await asyncio.sleep(0.5)

        except Exception as e:
            self.logger.error(f"❌ Unexpected error: {str(e)}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except ssl.SSLError as ssl_error:
                self.logger.warning(f"⚠️ SSL Error on close: {ssl_error}")

    def validate_and_match_id_data(self, id_data):
        try:
            decoded_data = base64.b64decode(id_data)
            if len(decoded_data) < 4:
                self.logger.error(
                    f"❌ Invalid voter_id_data length: {len(decoded_data)}")
                return None

            # ✅ Print raw bytes for debugging
            raw_bytes = decoded_data[:4]
            self.logger.info(f"🔍 Raw Voter ID Bytes: {raw_bytes.hex()}")

            # ✅ Try both big-endian and little-endian
            voter_id_big = struct.unpack(">I", raw_bytes)[0]  # Big-endian
            voter_id_little = struct.unpack("<I", raw_bytes)[
                0]  # Little-endian

            self.logger.info(
                f"🔹 Extracted voter_unique_id (Big-Endian): {voter_id_big}")
            self.logger.info(
                f"🔹 Extracted voter_unique_id (Little-Endian): {voter_id_little}")

            # ✅ Assume correct format is little-endian based on unexpected values
            return voter_id_little

        except Exception as e:
            self.logger.error(f"❌ Error decoding voter_id_data: {e}")
            return None

    async def start_server(self):
        ssl_context = self.create_ssl_context()
        server = await asyncio.start_server(self.handle_client, self.host, self.port, ssl=ssl_context)
        self.logger.info(
            f"✅ Voter ID Service started on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()

    def process_request(self, request_json):
        try:
            request_body = request_json.get("body", {})
            client_id = request_body.get("client_id_num")
            presented_id = request_body.get("voter_id_data")

            if not presented_id:
                return {"error": "Invalid request: Missing voter_id_data"}

            voter_unique_id = self.validate_and_match_id_data(presented_id)
            if voter_unique_id is None:
                return {"error": "Invalid voter ID data format"}

            response_body = {
                "presented_id": {
                    "body": {
                        "client_id_num": client_id,
                        "timestamp": request_body.get("timestamp", 0),
                        "voter_id_data": presented_id
                    },
                    "client_signature": request_json.get("client_signature", "INVALID_SIGNATURE")
                },
                "voter_unique_id": voter_unique_id
            }

            response_body_string = json.dumps(
                response_body, separators=(",", ":"))
            signature = self.private_key_signer.sign(
                response_body_string.encode(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )

            final_response = {
                "body": response_body,
                "id_service_signature": base64.b64encode(signature).decode("utf-8")
            }

            self.logger.info(f"🔹 Returning voter_unique_id: {voter_unique_id}")
            return final_response

        except Exception as e:
            self.logger.error(f"❌ Error processing request: {str(e)}")
            return {"error": "Failed to process request"}


async def main():
    config = configparser.ConfigParser()
    config.read("config.ini")
    logging.basicConfig(level=logging.INFO)

    voter_id_service = VoterIDService(config)
    await voter_id_service.start_server()

if __name__ == "__main__":
    asyncio.run(main())
