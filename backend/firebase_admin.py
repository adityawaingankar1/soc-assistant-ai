import firebase_admin
from firebase_admin import credentials
from loguru import logger
import os

if not firebase_admin._apps:
    try:
        cred_path = "/app/firebase-service-account.json"

        if not os.path.exists(cred_path):
            raise FileNotFoundError(
                f"Firebase service account not found: {cred_path}"
            )

        cred = credentials.Certificate(cred_path)

        firebase_admin.initialize_app(cred)

        logger.info("✅ Firebase Admin initialized")

    except Exception as e:
        logger.error(f"❌ Firebase initialization failed: {e}")