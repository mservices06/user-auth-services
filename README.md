# User Service

A microservice for user management and authentication.

## Project Structure

```
services/user-service/
├── src/
│   ├── config/       # Application configuration
│   ├── controllers/  # Request handlers
│   ├── middlewares/  # Express middlewares
│   ├── models/       # Data models
│   ├── routes/       # API routes
│   ├── services/     # Business logic
│   ├── utils/        # Utility functions
│   ├── prisma/       # Prisma ORM files
│   ├── app.js        # Express app setup
│   └── server.js     # Server entry point
├── tests/            # Test files
├── .env              # Environment variables (not in git)
├── .env.example      # Example environment variables
├── Dockerfile        # Docker container configuration
├── docker-compose.yml # Multi-container Docker setup
├── nodemon.json      # Nodemon configuration
└── package.json      # NPM package configuration
```

## Getting Started

### Prerequisites

- Node.js (v18+)
- Docker & Docker Compose
- PostgreSQL (if running locally)

### Installation

1. Clone the repository
2. Create a `.env` file based on `.env.example`
3. Install dependencies:
   ```
   npm install
   ```

### Development

```
npm run dev
```

### Production

```
npm start
```

## Docker

```
docker-compose up -d
```
