# LessShare - Front-end

<div align="center">
  A real-time file sharing application with peer-to-peer capabilities built with Vue 3, Vite, and WebRTC. Share files directly between peers with a modern, responsive interface.
</div>

## ✨ Features

- **Peer-to-Peer File Transfer**: Share files directly between users using WebRTC data channels
- **Real-time Chat**: Built-in chat functionality for communication
- **Room-based System**: Create and join rooms for organized sharing
- **Secure Transfers**: Direct peer-to-peer file sharing with WebRTC
- **Modern UI/UX**: Sleek, responsive interface with dark mode
- **Admin Dashboard**: User and room management
- **Drag & Drop**: Intuitive file sharing experience


## 🛠️ Tech Stack

- **Frontend Framework**: Vue 3 (Composition API)
- **Build Tool**: Vite
- **UI Framework**: Tailwind CSS
- **State Management**: Pinia
- **Real-time Communication**: Socket.IO, WebRTC
- **Charts**: ApexCharts
- **Routing**: Vue Router

## 📂 Project Structure

```
src/
├── assets/          # Static assets
├── components/      # Reusable Vue components
├── router/          # Vue Router configuration
├── stores/          # Pinia stores
└── views/           # Page components
    ├── AboutView.vue
    ├── AdminLoginView.vue
    ├── DashboardView.vue
    ├── HomeView.vue
    ├── HowItWorksView.vue
    ├── RoomView.vue
    └── UsernameView.vue
```

## 🔒 Security

- Environment variables for configuration
- Token-based authentication
- WebSocket connections (WSS) for real-time communication
- Input validation on client-side

> **Note**: For production use, consider implementing additional security measures such as:
> - End-to-end encryption for file transfers
> - File integrity verification
> - Rate limiting and abuse prevention
