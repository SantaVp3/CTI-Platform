# CTI Platform - Cyber Threat Intelligence Platform

A comprehensive web-based platform for managing cyber threat intelligence, indicators of compromise (IOCs), threat actors, campaigns, and security analysis.

## 🏗️ Architecture

- **Backend**: Go with Gin framework, GORM ORM
- **Frontend**: React with TypeScript, Tailwind CSS (embedded in binary)
- **Database**: MySQL 8.0+
- **Deployment**: Single binary with embedded frontend assets

## 📁 Project Structure

```
CTI_Platform/
├── backend/                 # Go backend application
│   ├── cmd/server/         # Main application entry point
│   ├── internal/           # Internal application code
│   │   ├── api/           # API handlers and routes
│   │   ├── config/        # Configuration management
│   │   ├── database/      # Database connection and setup
│   │   ├── middleware/    # HTTP middleware
│   │   ├── models/        # Data models
│   │   └── services/      # Business logic services
│   ├── web/               # Embedded frontend assets
│   │   ├── static/        # Compiled frontend files
│   │   └── embed.go       # Go embed configuration
│   ├── config/            # Configuration files
│   ├── go.mod             # Go module dependencies
│   └── go.sum             # Go module checksums
├── build.sh               # Build script for complete application
├── database_schema.sql     # Complete database schema
├── API_ENDPOINTS.md        # API documentation
└── README.md              # This documentation
```

**Note**: The frontend source code is not included in this repository as the compiled assets are embedded directly in the Go binary for easy deployment.

## 🚀 Quick Start

### Prerequisites

- Go 1.21+
- MySQL 8.0+
- Git

### Database Setup

1. Create a MySQL database:
```sql
CREATE DATABASE cti_platform;
```

2. Import the schema:
```bash
mysql -u your_user -p cti_platform < database_schema.sql
```

### Application Setup

1. Clone the repository:
```bash
git clone https://github.com/SantaVp3/CTI-Platform.git
cd CTI-Platform
```

2. Configure the database in `backend/config/config.yaml`:
```yaml
database:
  host: localhost
  port: 3306
  username: your_db_user
  password: your_db_password
  database: cti_platform
```

3. Run the application:
```bash
cd backend
go run ./cmd/server
```

The application will be available at `http://localhost:8080`

### Building a Binary

To create a standalone executable:
```bash
# From the project root
./build.sh
```

This creates a `cti-platform` binary in the `backend/` directory.

## 🔐 Default Login

- **Username**: admin
- **Password**: admin123
- **Note**: Change this password immediately in production!

## 🌟 Features

### Core Functionality
- **User Management**: Role-based access control (Admin, Analyst, Viewer)
- **IOC Management**: Comprehensive indicator tracking and analysis
- **Threat Actor Profiles**: Detailed threat actor intelligence
- **Campaign Tracking**: Multi-actor campaign management
- **Activity Timeline**: Threat activity tracking and correlation
- **Threat Feeds**: External feed integration and ingestion
- **Reports**: Intelligence report generation and sharing
- **STIX/TAXII**: Standards-compliant threat intelligence exchange

### Advanced Features
- **Settings Management**: System and user preference configuration
- **Security Policies**: Configurable security controls
- **Analysis Integration**: IOC analysis and enrichment
- **Audit Logging**: Complete activity tracking
- **API Access**: RESTful API with authentication
- **Real-time Updates**: Live data synchronization

## 📊 Database Schema

The platform uses a comprehensive database schema with the following main entities:

- **Users**: Authentication and authorization
- **Threat Actors**: Threat actor profiles and attributes
- **Campaigns**: Multi-actor campaign tracking
- **Activities**: Detailed activity timeline
- **IOCs**: Indicators of compromise with analysis
- **Reports**: Intelligence reports and documentation
- **Settings**: System and user configuration
- **Audit Logs**: Complete activity tracking

## 🔧 Development

### Development

To run the application in development mode:
```bash
cd backend
go run ./cmd/server
```

The application includes both backend API and frontend UI in a single binary.

### API Documentation
See `API_ENDPOINTS.md` for complete API documentation.

## 📝 License

This project is licensed under the MIT License.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Screenshot
<img width="1798" height="1152" alt="image" src="https://github.com/user-attachments/assets/dfb84b00-2578-41b0-a669-87e2ed0f2d18" />
<img width="1798" height="1152" alt="image" src="https://github.com/user-attachments/assets/3b6aa9af-2464-421d-bf62-b2152baf4bd8" />
<img width="1798" height="1152" alt="image" src="https://github.com/user-attachments/assets/001f8a22-a20b-4c24-8738-57888b4d0d2e" />
<img width="1798" height="1152" alt="image" src="https://github.com/user-attachments/assets/ef6b92ec-ff45-46a6-8d39-aac8b0e0aab4" />
<img width="1798" height="1152" alt="image" src="https://github.com/user-attachments/assets/415c16ef-59a5-4ea1-96c2-25f3d884517e" />
<img width="1798" height="1152" alt="image" src="https://github.com/user-attachments/assets/3e0e6335-7c81-4f31-8766-829798bd3db2" />
<img width="1798" height="1152" alt="image" src="https://github.com/user-attachments/assets/74d4003e-14fd-463d-b08b-1c3e1b69c290" />


## �📞 Support

For support and questions, please refer to the documentation or create an issue in the repository.
