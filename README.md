# 🐛 Bug Catcher

> A full-stack bug tracking and issue management application built with React + Node.js

![Bug Catcher Banner](docs/screenshots/banner.png)

## 📋 Table of Contents
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [API Documentation](#api-documentation)
- [Contributing](#contributing)
- [License](#license)

---

## ✨ Features

- 🔐 **Authentication** — JWT-based login/register with role management
- 🐛 **Bug Tracking** — Create, assign, update, and resolve bugs
- 📊 **Dashboard** — Real-time stats and charts for bug status
- 🏷️ **Labels & Priorities** — Categorize bugs with custom labels
- 💬 **Comments** — Threaded comments on each bug report
- 📎 **Attachments** — Upload screenshots and files to bug reports
- 🔔 **Notifications** — In-app and email notifications
- 👥 **Team Management** — Multi-user project collaboration
- 📱 **Responsive UI** — Mobile-friendly React frontend

---

## 🛠 Tech Stack

### Frontend
| Technology | Purpose |
|---|---|
| React 18 | UI Framework |
| React Router v6 | Client-side routing |
| Context API | State management |
| Axios | HTTP client |
| TailwindCSS | Styling |
| Chart.js | Dashboard charts |

### Backend
| Technology | Purpose |
|---|---|
| Node.js | Runtime |
| Express.js | Web framework |
| MongoDB + Mongoose | Database & ODM |
| JWT | Authentication |
| Bcrypt | Password hashing |
| Multer | File uploads |
| Nodemailer | Email notifications |

---

## 📁 Project Structure

```
bug-catcher/
├── frontend/                  # React application
│   ├── public/                # Static assets
│   └── src/
│       ├── components/        # Reusable UI components
│       │   ├── Auth/          # Login, Register forms
│       │   ├── Bugs/          # Bug list, detail, form
│       │   ├── Dashboard/     # Charts, stats widgets
│       │   ├── Layout/        # Navbar, Sidebar, Footer
│       │   └── UI/            # Buttons, Modals, Badges
│       ├── context/           # React Context providers
│       ├── hooks/             # Custom React hooks
│       ├── pages/             # Page-level components
│       ├── services/          # API service functions
│       ├── styles/            # Global CSS / Tailwind
│       └── utils/             # Helper functions
├── backend/                   # Express API server
│   ├── src/
│   │   ├── config/            # DB and app configuration
│   │   ├── controllers/       # Route handler logic
│   │   ├── middleware/        # Auth, error, validation
│   │   ├── models/            # Mongoose schemas
│   │   ├── routes/            # Express route definitions
│   │   ├── services/          # Business logic layer
│   │   └── utils/             # Helpers and utilities
│   └── tests/                 # Unit & integration tests
├── docs/                      # Documentation & screenshots
├── scripts/                   # Dev/deploy helper scripts
├── .gitignore
├── docker-compose.yml
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites
- Node.js >= 18.x
- MongoDB >= 6.x (local or Atlas)
- npm or yarn

### 1. Clone the repository
```bash
git clone https://github.com/MissDaze/bug-catcher.git
cd bug-catcher
```

### 2. Install dependencies
```bash
# Install backend dependencies
cd backend && npm install

# Install frontend dependencies
cd ../frontend && npm install
```

### 3. Configure environment variables
```bash
# Backend
cp backend/.env.example backend/.env
# Edit backend/.env with your values

# Frontend
cp frontend/.env.example frontend/.env
# Edit frontend/.env with your values
```

### 4. Start development servers
```bash
# From root directory - start both servers
npm run dev

# Or start individually:
cd backend && npm run dev
cd frontend && npm start
```

Frontend: http://localhost:3000  
Backend API: http://localhost:5000

### 5. Docker (optional)
```bash
docker-compose up --build
```

---

## 🔑 Environment Variables

### Backend (`backend/.env`)
```env
NODE_ENV=development
PORT=5000
MONGO_URI=mongodb://localhost:27017/bugcatcher
JWT_SECRET=your_jwt_secret_here
JWT_EXPIRE=7d
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your@email.com
EMAIL_PASS=your_email_password
CLIENT_URL=http://localhost:3000
```

### Frontend (`frontend/.env`)
```env
REACT_APP_API_URL=http://localhost:5000/api
REACT_APP_NAME=Bug Catcher
```

---

## 📚 API Documentation

See [docs/api/](docs/api/) for full API reference.

### Key Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register new user |
| POST | `/api/auth/login` | Login user |
| GET | `/api/bugs` | List all bugs |
| POST | `/api/bugs` | Create new bug |
| GET | `/api/bugs/:id` | Get bug details |
| PUT | `/api/bugs/:id` | Update bug |
| DELETE | `/api/bugs/:id` | Delete bug |
| POST | `/api/bugs/:id/comments` | Add comment |
| GET | `/api/projects` | List projects |
| GET | `/api/users/me` | Get current user |

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

*Built with ❤️ by [MissDaze](https://github.com/MissDaze)*
