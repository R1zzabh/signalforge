import os

DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"
DATABASE_PATH = os.getenv("DATABASE_PATH", os.path.join(os.path.dirname(os.path.dirname(__file__)), "soc.db"))
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./soc.db")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
