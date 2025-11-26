# LessShare - Back-end

> **Note:** This project has not been refactored yet. Refactoring is planned for a future update to improve code organization and maintainability.

Backend service for LessShare, a real-time file sharing and collaboration platform built with Node.js, Express, and Socket.IO.

## ✨ Features

- Real-time file sharing and messaging
- User authentication with JWT
- Room-based collaboration
- File uploads and metadata management
- WebSocket support for real-time updates
- RESTful API endpoints

## 🚀 Getting Started



## 🔧 Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
PORT=3000
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret_key
CORS_ORIGINS=http://localhost:3000,http://localhost:3001
```

## 📚 API Documentation

### Authentication

- `POST /api/users` - Register a new user
- `POST /api/auth/login` - Login and get JWT token

### Rooms

- `POST /api/rooms` - Create a new room
- `GET /api/rooms` - Get all rooms
- `GET /api/rooms/:roomId` - Get room details
- `POST /api/rooms/:roomId/messages` - Send a message to a room

### Files

- `POST /api/upload` - Upload a file
- `GET /api/files/:fileId` - Get file information
- `DELETE /api/files/:fileId` - Delete a file

## 🌐 WebSocket Events

The following WebSocket events are supported:

- `join-room` - Join a room
- `leave-room` - Leave a room
- `chat-message` - Send a chat message
- `file-upload` - Notify about file upload
- `file-metadata` - Share file metadata with room participants

