import strawberry
from sqlalchemy.orm import Session
from sqlalchemy import select
from uuid import UUID as PyUUID

from models import UserModel


@strawberry.type
class User:
    id: str
    email: str
    first_name: str
    last_name: str
    created_at: str  # this is an ISO string (timestamp)


def to_graphql_user(u: UserModel) -> User:
    return User(
        id=str(u.id),
        email=u.email,
        first_name=u.first_name,
        last_name=u.last_name,
        created_at=u.created_at.isoformat() if u.created_at else "",
    )


@strawberry.type
class Query:
    @strawberry.field
    def users(self, info) -> list[User]:
        db: Session = info.context["db"]
        rows = (
            db.execute(select(UserModel).order_by(UserModel.created_at.desc()))
            .scalars()
            .all()
        )
        return [to_graphql_user(u) for u in rows]

    @strawberry.field
    def user_by_id(self, info, id: str) -> User | None:
        db: Session = info.context["db"]
        row = db.get(UserModel, PyUUID(id))
        return to_graphql_user(row) if row else None

    @strawberry.field
    def user_by_email(self, info, email: str) -> User | None:
        db: Session = info.context["db"]
        row = db.execute(
            select(UserModel).where(UserModel.email == email)
        ).scalar_one_or_none()
        return to_graphql_user(row) if row else None


@strawberry.type
class Mutation:
    @strawberry.mutation
    def create_user(self, info, email: str, first_name: str, last_name: str) -> User:
        db: Session = info.context["db"]

        existing = db.execute(
            select(UserModel).where(UserModel.email == email)
        ).scalar_one_or_none()
        if existing:
            raise ValueError("Email already exists")

        user = UserModel(email=email, first_name=first_name, last_name=last_name)
        db.add(user)
        db.commit()
        db.refresh(user)
        return to_graphql_user(user)


schema = strawberry.Schema(query=Query, mutation=Mutation)
