import os  # Ensure this is included at the top of the script
import asyncio
import json
import ssl
import logging
import configparser
import base64
import struct
import cv2
import pandas as pd
import pytesseract
import numpy as np  # ✅ Add this line
from PIL import Image
from io import BytesIO
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key


# Database file
DB_FILE = "voter_db.csv"


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

    def load_voter_database(self):
        """Load the voter database from CSV, ensuring it exists."""
        db_path = "voter_db.csv"  # Path to the CSV file

        if not os.path.exists(db_path):
            self.logger.error(
                "❌ Voter database file is missing! Please create 'voter_db.csv'.")
            return None  # Return None if database doesn't exist

        try:
            # Ensure all data is read as strings
            df = pd.read_csv(db_path, dtype=str)
            # Replace NaN with empty strings for consistency
            df = df.fillna("")
            df["license_number"] = df["license_number"].str.lower().str.strip()
            #df["middle_name"] = df["middle_name"].str.lower().str.strip()
            #df["last_name"] = df["last_name"].str.lower().str.strip()
            return df
        except Exception as e:
            self.logger.error(f"❌ Error reading voter database: {e}")
            return None

    async def start_server(self):
        ssl_context = self.create_ssl_context()
        server = await asyncio.start_server(self.handle_client, self.host, self.port, ssl=ssl_context)
        self.logger.info(
            f"✅ Voter ID Service started on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()

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
                self.logger.info(f"📥 Parsed JSON request: {json.dumps(request_json, indent=2)}")

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

    def process_request(self, request_json):
        try:
            request_body = request_json.get("body", {})
            presented_id = request_body.get("voter_id_data")

            if not presented_id:
                return {"error": "Invalid request: Missing voter_id_data"}

            extracted_text = self.process_voter_image(presented_id)
            if extracted_text is None:
                return {"error": "Failed to extract text from image"}

            match_result = self.match_voter_in_database(extracted_text)
            if "error" in match_result:
                return {"error": match_result["error"]}

            try:
                voter_uid = int(match_result["voter_unique_id"])
            except (ValueError, TypeError):
                self.logger.error(f"❌ Invalid voter_unique_id format: {match_result['voter_unique_id']}")
                return {"error": "Invalid voter ID format"}

            response_body = {
                "presented_id": {
                    "body": request_body,
                    "client_signature": request_json.get("client_signature", "INVALID_SIGNATURE"),
                },
                "voter_unique_id": voter_uid,
                "name": match_result["name"],
                "address": match_result["address"]
            }


            # 🔐 Sign the response body
            to_be_signed = {
                "presented_id": response_body["presented_id"],
                "voter_unique_id": response_body["voter_unique_id"]
            }
            response_data = json.dumps(to_be_signed, separators=(',', ':'), sort_keys=True).encode()

            signature = self.private_key_signer.sign(
                response_data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            signature_b64 = base64.b64encode(signature).decode()

            return {
                "body": response_body,
                "id_service_signature": signature_b64
            }

        except Exception as e:
            self.logger.error(f"❌ Unexpected error processing request: {e}")
            return {"error": "Server error, please try again later"}

    def process_voter_image(self, encoded_image):
        """Decode and process the ID image to extract voter details."""
        try:
            # Decode base64 image
            image_data = base64.b64decode(encoded_image)
            image = Image.open(BytesIO(image_data)).convert("RGB")

            # Convert to OpenCV
            image_cv = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)

            # ✅ Rotate the image if needed (based on width vs. height)
            if image_cv.shape[0] > image_cv.shape[1]:
                image_cv = cv2.rotate(image_cv, cv2.ROTATE_90_COUNTERCLOCKWISE)

            # ✅ Resize to make text bigger
            image_cv = cv2.resize(image_cv, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)

            # ✅ Denoise and grayscale
            denoised = cv2.bilateralFilter(image_cv, d=13, sigmaColor=75, sigmaSpace=75)
            gray = cv2.cvtColor(denoised, cv2.COLOR_BGR2GRAY)

            # ✅ Adaptive Threshold
            thresh = cv2.adaptiveThreshold(
                gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                cv2.THRESH_BINARY, 31, 2
            )

            # ✅ Save processed image (for debugging)
            cv2.imwrite("processed_id_debug.jpg", thresh)

            # ✅ Run OCR with better config
            custom_config = r'--oem 3 --psm 6'
            extracted_text = pytesseract.image_to_string(thresh, config=custom_config)

            extracted_text = extracted_text.lower().replace("\n", " ").strip()
            self.logger.info(f"🔍 Extracted text from image:\n{extracted_text}")
            return extracted_text

        except Exception as e:
            self.logger.error(f"❌ Error processing voter image: {e}")
            return None

    def match_voter_in_database(self, extracted_text):
        """Match extracted text against the 'license_number' field in the CSV."""
        try:
            df = pd.read_csv("voter_db.csv", dtype=str)
            df["license_number"] = df["license_number"].str.strip()

            for _, row in df.iterrows():
                if row["license_number"] in extracted_text:
                    self.logger.info(f"✅ Found match: {row.to_dict()}")
                    return {
                        "voter_unique_id": row["license_number"],
                        "name": row["name"],
                        "address": row["address"]
                    }

            self.logger.info(f"🔍 Matching against extracted text: {extracted_text}")

            return {"error": "No matching voter found."}

        except Exception as e:
            self.logger.error(f"❌ Error reading voter database: {e}")
            return {"error": "Failed to read voter database"}


async def main():
    config = configparser.ConfigParser()
    config.read("config.ini")
    logging.basicConfig(level=logging.INFO)

    voter_id_service = VoterIDService(config)
    await voter_id_service.start_server()


if __name__ == "__main__":
    asyncio.run(main())
