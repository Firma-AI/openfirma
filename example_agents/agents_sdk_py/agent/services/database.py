import os

from sqlalchemy import create_engine, text

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.path.join(_BASE_DIR, ".data", "firma.db")
SEED_PATH = os.path.join(_BASE_DIR, "seed.sql")

_engine = None


def get_engine():
    global _engine
    if _engine is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        _engine = create_engine(f"sqlite:///{DB_PATH}")
    return _engine


def initialize_database() -> None:
    engine = get_engine()

    if not os.path.exists(SEED_PATH):
        print(f"firma-agent: Seed file not found at {SEED_PATH}, skipping initialization")
        return

    seed_sql = open(SEED_PATH).read()

    with engine.connect() as conn:
        for statement in seed_sql.split(";"):
            statement = statement.strip()
            if statement:
                conn.execute(text(statement))
        conn.commit()

    print("firma-agent: Database initialized with seed data")
