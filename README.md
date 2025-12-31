# User Service

A comprehensive user management microservice built with Python/FastAPI and GraphQL, featuring Keycloak authentication integration for the Parkora smart parking system.

## 🚀 Features

- **GraphQL API**: Complete user CRUD operations with Strawberry GraphQL
- **Keycloak Integration**: JWT token verification for secure authentication
- **Synced User Profiles**: Links user data with Keycloak users via `keycloak_user_id`
- **PostgreSQL Database**: Robust data persistence with SQLAlchemy ORM
- **Comprehensive Testing**: 11 test cases covering all GraphQL operations
- **Production Ready**: Docker, Helm charts, and Kubernetes manifests
- **CI/CD Pipeline**: Automated linting, testing, building, and deployment

## 🏗️ Architecture

### Tech Stack
- **Framework**: FastAPI with async support
- **GraphQL**: Strawberry GraphQL library
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Authentication**: Keycloak JWT token verification
- **Container**: Docker with multi-platform builds
- **Orchestration**: Kubernetes with Helm charts

### Data Model
```sql
User {
    id: UUID (Primary Key)
    email: String (Unique)
    keycloak_user_id: UUID (Unique, Nullable)
    first_name: String
    last_name: String
    created_at: DateTime
}
```

## 📋 Prerequisites

- Python 3.11+
- PostgreSQL database
- Keycloak instance (for authentication)
- Docker (for containerization)
- Kubernetes cluster (for deployment)

## 🛠️ Setup & Installation

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/sample-unwind/user-service.git
   cd user-service
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Run database migrations** (if using Alembic)
   ```bash
   # Add migration commands if needed
   ```

6. **Start the development server**
   ```bash
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

The service will be available at:
- **API**: `http://localhost:8000`
- **GraphQL**: `http://localhost:8000/graphql`
- **API Docs**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DATABASE_URL` | PostgreSQL connection string | - | Yes |
| `KEYCLOAK_URL` | Keycloak server URL | `https://keycloak.parkora.crn.si/auth/` | Yes |
| `KEYCLOAK_REALM` | Keycloak realm name | `parkora` | Yes |
| `KEYCLOAK_CLIENT_ID` | Keycloak client ID | `backend-services` | Yes |
| `KEYCLOAK_CLIENT_SECRET` | Keycloak client secret | - | Yes |

### Sample .env file
```env
DATABASE_URL=postgresql://user:password@localhost:5432/user_service
KEYCLOAK_URL=https://keycloak.parkora.crn.si/auth/
KEYCLOAK_REALM=parkora
KEYCLOAK_CLIENT_ID=backend-services
KEYCLOAK_CLIENT_SECRET=your-client-secret-here
```

## 📡 API Documentation

### OpenAPI Documentation

FastAPI automatically generates interactive API documentation:

- **Swagger UI**: `/docs` - Interactive API documentation
- **ReDoc**: `/redoc` - Alternative documentation format
- **OpenAPI JSON**: `/openapi.json` - Machine-readable API specification

### GraphQL Endpoint
- **URL**: `/graphql`
- **Method**: POST
- **Content-Type**: `application/json`

### Authentication
Include JWT token in Authorization header:
```
Authorization: Bearer <jwt-token>
```

### GraphQL Schema

#### Queries

**Get all users**
```graphql
query {
  users {
    id
    email
    keycloakUserId
    firstName
    lastName
    createdAt
  }
}
```

**Get user by ID**
```graphql
query GetUser($id: String!) {
  userById(id: $id) {
    id
    email
    keycloakUserId
    firstName
    lastName
    createdAt
  }
}
```

**Get user by Email**
```graphql
query GetUserByEmail($email: String!) {
  userByEmail(email: $email) {
    id
    email
    keycloakUserId
    firstName
    lastName
    createdAt
  }
}
```

**Get user by Keycloak ID**
```graphql
query GetUserByKeycloakId($keycloakUserId: String!) {
  userByKeycloakId(keycloakUserId: $keycloakUserId) {
    id
    email
    keycloakUserId
    firstName
    lastName
    createdAt
  }
}
```

#### Mutations

**Create user**
```graphql
mutation CreateUser($input: CreateUserInput!) {
  createUser(
    email: $input.email
    firstName: $input.firstName
    lastName: $input.lastName
    keycloakUserId: $input.keycloakUserId
  ) {
    id
    email
    keycloakUserId
    firstName
    lastName
    createdAt
  }
}
```

**Update user** (placeholder - not implemented yet)
```graphql
mutation UpdateUser($id: String!, $input: UpdateUserInput!) {
  updateUser(id: $id, input: $input) {
    id
    email
    firstName
    lastName
  }
}
```

**Delete user** (placeholder - not implemented yet)
```graphql
mutation DeleteUser($id: String!) {
  deleteUser(id: $id) {
    success
    message
  }
}
```

### Health Checks

**Liveness Probe**
- **URL**: `/health/live`
- **Method**: GET
- **Response**: `{"status": "alive", "service": "user-service", "version": "1.0.0"}`

**Readiness Probe**
- **URL**: `/health/ready`
- **Method**: GET
- **Response**: `{"status": "ready", "service": "user-service", "version": "1.0.0"}`

### User Statistics

**Get User Stats**
- **URL**: `/stats`
- **Method**: GET
- **Response**:
```json
{
  "total_users": 5,
  "users_with_keycloak_id": 3,
  "recent_users": 2
}
```

### API Root

**Service Information**
- **URL**: `/`
- **Method**: GET
- **Response**:
```json
{
  "message": "User Service API",
  "version": "1.0.0",
  "docs": "/docs",
  "graphql": "/graphql",
  "health": {
    "live": "/health/live",
    "ready": "/health/ready"
  }
}
```

## 🧪 Testing

### Run Tests
```bash
# Install test dependencies (included in requirements.txt)
pip install pytest pytest-asyncio

# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_graphql.py -v
```

### Test Coverage
- **GraphQL Queries**: All user retrieval operations
- **GraphQL Mutations**: User creation with validation
- **Authentication**: Token verification (integration tests)
- **Database**: CRUD operations and constraints
- **Error Handling**: Validation and constraint violations

**Test Results**: 11 tests passing ✅

## 🚀 Deployment

### Docker

**Build image**
```bash
docker build -t user-service:latest .
```

**Run container**
```bash
docker run -p 8000:8000 --env-file .env user-service:latest
```

### Kubernetes with Helm

**Install service**
```bash
helm upgrade --install user-service ./helm/user-service \
  --namespace parkora \
  --set image.tag=latest
```

**Check deployment**
```bash
kubectl get pods -n parkora
kubectl logs -n parkora deployment/user-service
```

### CI/CD Pipeline

The service uses GitHub Actions for automated CI/CD:

- **Triggers**: Push to main, pull requests, releases
- **Linting**: black, mypy, isort, flake8
- **Testing**: pytest with SQLite in-memory database
- **Build**: Multi-platform Docker images (amd64, arm64)
- **Registry**: GitHub Container Registry (GHCR)
- **Deployment**: Automated Helm upgrades to AKS

See `.github/workflows/ci-cd.yml` for complete pipeline configuration.

## 🔒 Security

- **JWT Authentication**: All GraphQL operations require valid Keycloak JWT tokens
- **Input Validation**: Comprehensive validation for all GraphQL inputs
- **SQL Injection Protection**: SQLAlchemy ORM prevents injection attacks
- **Secrets Management**: Azure Key Vault integration for production secrets
- **CORS**: Configured for cross-origin requests from frontend

## 📊 Monitoring

- **Health Checks**: Kubernetes readiness/liveness probes
- **Metrics**: FastAPI built-in metrics endpoint (future enhancement)
- **Logging**: Structured logging with request IDs
- **Tracing**: OpenTelemetry integration (future enhancement)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- **Code Style**: Black formatting, isort imports
- **Type Hints**: Full mypy type coverage required
- **Testing**: 100% test coverage for new features
- **Documentation**: Update README for API changes
- **Commits**: Conventional commit messages

## 📄 License

This project is part of the Parkora smart parking system.

## 🆘 Troubleshooting

### Common Issues

**Database connection failed**
- Check `DATABASE_URL` environment variable
- Ensure PostgreSQL is running and accessible

**Keycloak authentication failed**
- Verify `KEYCLOAK_*` environment variables
- Check Keycloak server connectivity
- Validate JWT token format

**GraphQL queries return null**
- Check authentication header
- Verify user exists in database
- Check application logs for errors

### Logs

```bash
# View application logs
kubectl logs -n parkora deployment/user-service -f

# View GraphQL request logs
# Logs include request IDs for tracing
```

## 📞 Support

For issues and questions:
- Create an issue in the GitHub repository
- Check existing issues for similar problems
- Review the troubleshooting section above

---

**Built with ❤️ for the Parkora smart parking system**