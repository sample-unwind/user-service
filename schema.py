"""
GraphQL Schema for User Service

Provides queries and mutations for user management.
Uses PostgreSQL RLS for automatic tenant isolation.
tenantId is NOT exposed in the GraphQL API (hidden).
"""

from datetime import datetime
from typing import cast
from uuid import UUID as PyUUID

import strawberry
from sqlalchemy import select
from sqlalchemy.orm import Session

from models import UserModel


@strawberry.type
class User:
    """User type - tenantId is intentionally hidden."""

    id: str
    email: str
    keycloak_user_id: str
    first_name: str
    last_name: str
    created_at: str  # ISO string


@strawberry.type
class DeleteResult:
    success: bool


def to_graphql_user(u: UserModel) -> User:
    """Convert SQLAlchemy model to GraphQL type."""
    created_at = cast(datetime | None, u.created_at)
    return User(
        id=str(u.id),
        email=u.email,
        keycloak_user_id=str(u.keycloak_user_id),
        first_name=u.first_name,
        last_name=u.last_name,
        created_at=created_at.isoformat() if created_at else "",
    )


def get_tenant_id(info) -> str:
    """Get tenant_id from context, raising error if not present."""
    tenant_id = info.context.get("tenant_id")
    if not tenant_id:
        raise ValueError("Tenant ID is required (X-Tenant-ID header)")
    return tenant_id


@strawberry.type
class Query:
    @strawberry.field
    def users(self, info) -> list[User]:
        """Get all users for the current tenant."""
        db: Session = info.context["db"]
        # RLS automatically filters by tenant
        rows = (
            db.execute(select(UserModel).order_by(UserModel.created_at.desc()))
            .scalars()
            .all()
        )
        return [to_graphql_user(u) for u in rows]

    @strawberry.field
    def user_by_id(self, info, id: str) -> User | None:
        """Get user by ID (within current tenant)."""
        db: Session = info.context["db"]
        # RLS ensures we can only get users from our tenant
        row = db.get(UserModel, PyUUID(id))
        return to_graphql_user(row) if row else None

    @strawberry.field
    def user_by_email(self, info, email: str) -> User | None:
        """Get user by email (within current tenant)."""
        db: Session = info.context["db"]
        row = db.execute(
            select(UserModel).where(UserModel.email == email)
        ).scalar_one_or_none()
        return to_graphql_user(row) if row else None

    @strawberry.field
    def user_by_keycloak_id(self, info, keycloak_user_id: str) -> User | None:
        """Get user by Keycloak ID (within current tenant)."""
        db: Session = info.context["db"]
        row = db.execute(
            select(UserModel).where(
                UserModel.keycloak_user_id == PyUUID(keycloak_user_id)
            )
        ).scalar_one_or_none()
        return to_graphql_user(row) if row else None


@strawberry.type
class Mutation:
    @strawberry.mutation
    def create_user(
        self,
        info,
        email: str,
        first_name: str,
        last_name: str,
        keycloak_user_id: str,  # Mandatory - no default
    ) -> User:
        """
        Create a new user.

        Requires X-Tenant-ID header.
        keycloak_user_id is mandatory.
        Email must be unique within the tenant.
        """
        db: Session = info.context["db"]
        tenant_id = get_tenant_id(info)

        # Check email uniqueness within tenant (RLS already filters by tenant)
        existing_email = db.execute(
            select(UserModel).where(UserModel.email == email)
        ).scalar_one_or_none()
        if existing_email:
            raise ValueError("Email already exists in this tenant")

        # Check keycloak_user_id uniqueness within tenant
        existing_keycloak = db.execute(
            select(UserModel).where(
                UserModel.keycloak_user_id == PyUUID(keycloak_user_id)
            )
        ).scalar_one_or_none()
        if existing_keycloak:
            raise ValueError("Keycloak user ID already exists in this tenant")

        user = UserModel(
            tenant_id=PyUUID(tenant_id),
            email=email,
            first_name=first_name,
            last_name=last_name,
            keycloak_user_id=PyUUID(keycloak_user_id),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return to_graphql_user(user)

    @strawberry.mutation
    def update_user(
        self,
        info,
        id: str,
        email: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
    ) -> User:
        """
        Update an existing user.

        Can only update users within the current tenant (RLS enforced).
        """
        db: Session = info.context["db"]

        # RLS ensures we can only get users from our tenant
        user = db.get(UserModel, PyUUID(id))
        if not user:
            raise ValueError("User not found")

        if email is not None and email != user.email:
            # Check uniqueness within tenant
            existing = db.execute(
                select(UserModel).where(UserModel.email == email)
            ).scalar_one_or_none()
            if existing:
                raise ValueError("Email already exists in this tenant")
            user.email = email

        if first_name is not None:
            user.first_name = first_name
        if last_name is not None:
            user.last_name = last_name

        db.commit()
        db.refresh(user)
        return to_graphql_user(user)

    @strawberry.mutation
    def delete_user(self, info, id: str) -> DeleteResult:
        """
        Delete a user.

        Can only delete users within the current tenant (RLS enforced).
        """
        db: Session = info.context["db"]

        user = db.get(UserModel, PyUUID(id))
        if not user:
            return DeleteResult(success=False)

        db.delete(user)
        db.commit()
        return DeleteResult(success=True)


schema = strawberry.Schema(query=Query, mutation=Mutation)
