from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from strawberry.fastapi import GraphQLRouter
from sqlalchemy.orm import Session

from db import get_db, engine
from schema import schema

app = FastAPI(title="User Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health/live")
def health_live():
    return {"status": "alive"}

@app.get("/health/ready")
def health_ready():
    return {"status": "ready"}

@app.get("/")
def root():
    return {"message": "User Service API"}

def get_context(db: Session = Depends(get_db)):
    return {"db": db}

app.include_router(GraphQLRouter(schema, context_getter=get_context), prefix="/graphql")