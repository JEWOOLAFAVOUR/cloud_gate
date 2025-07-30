# Cloud Guard - Zero Trust Architecture

A comprehensive Zero Trust Architecture implementation for cloud security featuring React frontend, Node.js backend, and Azure integration with multi-factor authentication and real-time threat monitoring.

## 🛡️ Features

### Security & Authentication

- **Zero Trust Architecture**: "Never trust, always verify" security model
- **Multi-Factor Authentication (MFA)**: TOTP-based 2FA support
- **JWT Token Management**: Secure access and refresh token system
- **Device Fingerprinting**: Track and manage known devices
- **Account Lockout Protection**: Automatic lockout after failed attempts
- **Role-Based Access Control (RBAC)**: Admin, user, and custom roles

### Dashboard & Monitoring

- **Real-time Security Metrics**: Live threat monitoring and statistics
- **Security Event Timeline**: Track security events with severity levels
- **User Management**: Comprehensive user administration
- **Policy Enforcement**: Security policy management and compliance
- **Risk Assessment**: Dynamic risk scoring and threat analysis

### Cloud Integration

- **Azure Cosmos DB**: Scalable NoSQL database for user data
- **Azure Key Vault**: Secure secret and key management
- **Azure Storage**: Blob storage for logs and artifacts
- **Redis**: Session management and caching
- **Azure Active Directory**: Enterprise identity integration

## 🚀 Quick Start

### Prerequisites

- Node.js 18+
- npm or yarn
- Redis (optional for MVP mode)
- Azure account (optional for production)

### Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/JEWOOLAFAVOUR/cloud_guard.git
   cd cloud_guard
   ```

2. **Setup Backend**

   ```bash
   cd backend
   npm install
   cp .env.example .env
   # Edit .env with your configuration
   npm run dev
   ```

3. **Setup Frontend**

   ```bash
   cd ../frontend
   npm install
   npm run dev
   ```

4. **Access the Application**
   - Frontend: http://localhost:5173
   - Backend API: http://localhost:3001
   - Health Check: http://localhost:3001/health

### Demo Credentials

```
Email: admin@cloudguard.com
Password: password123
```

## 📁 Project Structure

```
cloud_guard/
├── backend/                 # Node.js Express API
│   ├── src/
│   │   ├── middleware/     # Authentication, error handling
│   │   ├── routes/         # API endpoints
│   │   ├── utils/          # Azure clients, logging, helpers
│   │   └── server.ts       # Main server file
│   ├── dist/               # Compiled TypeScript
│   └── package.json
├── frontend/               # React TypeScript UI
│   ├── src/
│   │   ├── components/     # React components
│   │   │   ├── auth/       # Login, MFA components
│   │   │   ├── dashboard/  # Dashboard views
│   │   │   ├── layout/     # Navigation, sidebar
│   │   │   └── ui/         # Reusable UI components
│   │   ├── contexts/       # React contexts
│   │   ├── lib/            # API client, utilities
│   │   └── App.tsx         # Main app component
│   └── package.json
└── README.md
```

## 🔧 Configuration

### Backend Environment Variables

```bash
# Server
NODE_ENV=development
PORT=3001
FRONTEND_URL=http://localhost:5173

# Database
DB_CONNECTION_STRING=your_cosmos_db_connection_string

# JWT
JWT_SECRET=your_super_secret_jwt_key
JWT_REFRESH_SECRET=your_super_secret_refresh_key
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# Azure (Production)
AZURE_CLIENT_ID=your_azure_client_id
AZURE_CLIENT_SECRET=your_azure_client_secret
AZURE_TENANT_ID=your_azure_tenant_id
AZURE_KEY_VAULT_URL=https://your-keyvault.vault.azure.net/

# MVP Mode (Development)
MVP_MODE=true
```

## 🏗️ Architecture

### Zero Trust Principles

1. **Verify Identity**: Multi-factor authentication for all users
2. **Validate Device**: Device fingerprinting and known device tracking
3. **Assess Risk**: Dynamic risk scoring based on behavior patterns
4. **Enforce Policy**: Role-based access control and security policies
5. **Monitor Continuously**: Real-time security event monitoring

### Technology Stack

**Frontend:**

- React 18 with TypeScript
- Vite for fast development
- Tailwind CSS + shadcn/ui for styling
- React Hook Form for form management
- Axios for API communication

**Backend:**

- Node.js + Express.js
- TypeScript for type safety
- JWT for authentication
- Winston for logging
- Express Rate Limiting
- Helmet for security headers

**Cloud Services:**

- Azure Cosmos DB (NoSQL database)
- Azure Key Vault (Secret management)
- Azure Storage (File storage)
- Redis (Session caching)

## 🔒 Security Features

### Authentication Flow

1. User submits credentials
2. Server validates against secure hash
3. Optional MFA token verification
4. Device fingerprint validation
5. JWT tokens generated and returned
6. Refresh token rotation on expiry

### Security Middleware

- **Rate Limiting**: Prevent brute force attacks
- **CORS Protection**: Cross-origin request security
- **Helmet**: Security headers (CSP, HSTS, etc.)
- **Input Validation**: Request sanitization and validation
- **Error Handling**: Secure error responses

## 📊 API Endpoints

### Authentication

- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/me` - Get current user
- `POST /api/auth/refresh` - Refresh tokens
- `POST /api/auth/setup-mfa` - Setup MFA
- `POST /api/auth/verify-mfa` - Verify MFA token

### Dashboard

- `GET /api/dashboard/stats` - Security statistics
- `GET /api/dashboard/events` - Recent security events
- `GET /api/dashboard/metrics` - Performance metrics

### Users & Security

- `GET /api/users` - List users (admin)
- `GET /api/security/policies` - Security policies
- `POST /api/security/scan` - Trigger security scan

## 🚀 Deployment

### Development Mode

```bash
# Backend
cd backend && npm run dev

# Frontend
cd frontend && npm run dev
```

### Production Build

```bash
# Backend
cd backend && npm run build && npm start

# Frontend
cd frontend && npm run build
```

### Docker Support (Coming Soon)

- Multi-stage Docker builds
- Docker Compose for local development
- Kubernetes manifests for cloud deployment

## 🧪 Testing

```bash
# Backend tests
cd backend && npm test

# Frontend tests
cd frontend && npm test

# E2E tests
npm run test:e2e
```

## 📈 Monitoring & Logging

- **Winston Logging**: Structured JSON logs
- **Health Checks**: `/health` endpoint for monitoring
- **Security Events**: Audit trail for all security actions
- **Performance Metrics**: Response times and error rates

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🛠️ Development Status

- ✅ **MVP Complete**: Basic authentication and dashboard
- ✅ **Zero Trust Core**: Identity verification and policy enforcement
- 🚧 **Azure Integration**: Production cloud services setup
- 🚧 **Advanced MFA**: Hardware key and biometric support
- 📋 **Planned**: Machine learning threat detection

## 📞 Support

For support and questions:

- Create an issue on GitHub
- Check the [documentation](docs/)
- Review the [FAQ](docs/FAQ.md)

---

**Built with ❤️ for enterprise security**
