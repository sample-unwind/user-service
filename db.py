import logging
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from models import Base

# Set up logging
logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE URL not found in env variables.")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Create database tables with error handling
try:
    logger.info("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully")
except Exception as e:
    logger.error(f"Failed to create database tables: {e}")
    # Don't crash the application if table creation fails
    # Tables might already exist or permissions might be insufficient
    logger.warning("Continuing without table creation - tables may need to be created manually")
