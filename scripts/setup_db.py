import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.database import initialize_database


if __name__ == "__main__":
    initialize_database()
    print("TrustVault database and private storage directory are ready.")