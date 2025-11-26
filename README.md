# LessShare: Decentralized Peer-to-Peer File Sharing System

> **Project Structure & Status**  
> - This project is currently not refactored. Refactoring is planned for a future update to improve code organization and maintainability.
> - The project is divided into two main components:
>   - **Frontend**: Vue 3 application with real-time file sharing and chat features ([README](./lessshare-frontend/README.md))
>   - **Backend**: Node.js/Express server with WebSocket support ([README](./lessshare-backend/README.md))
> - Each component has its own setup instructions and dependencies. Please refer to their respective README files for detailed information.

## 🚀 Thesis Title
**Design and Implementation of a Decentralized Peer-to-Peer File Sharing System**

This project proposes and implements a secure, browser-native, decentralized file-sharing system, leveraging **WebRTC (Web Real-Time Communication)** to enable direct, end-to-end encrypted transfers between users without relying on centralized cloud storage servers.

It addresses the critical limitations of traditional centralized solutions, which suffer from privacy vulnerabilities, single points of failure, and inherent censorship risks.


## ✨ Features

- **Peer-to-Peer (P2P) Transfers**: Files are transferred directly between peers (browsers) using WebRTC Data Channels, bypassing intermediary storage servers.  
- **Browser-Native Solution**: No plugins, extensions, or dedicated desktop applications are required. The entire system operates within a modern web browser.  
- **Large File Support**: Optimized for efficient transfer of files up to 1GB through adaptive 65KB chunking and parallel transmission.  
- **NAT Traversal**: Utilizes the ICE framework with STUN servers for robust connectivity across diverse network conditions.  
- **Metadata Preservation**: Ensures the original filenames and formats are accurately retained upon file reconstruction.  

---

## 💻 Technical Stack

| Component         | Technology           | Purpose |
|------------------|-------------------|---------|
| **P2P Communication** | WebRTC Data Channels | Establishes direct, encrypted, high-speed data links between peers. |
| **Signaling**     | Socket.io / Express.js | Coordinates the initial connection setup (offer/answer exchange) and peer discovery. |
| **Frontend**      | Vue.js               | Provides a responsive, component-based UI for file selection and transfer monitoring. |
| **Backend**       | Express.js / Node.js | Hosts the lightweight signaling server. |
| **Protocols**     | STUN/TURN/ICE       | Handles NAT traversal to ensure connectivity. |

---

## 📐 Architecture Overview

The system operates on a hybrid model:

1. **Signaling Phase**: Users connect to a central, lightweight Signaling Server (Socket.io). This server acts only as a matchmaker, exchanging metadata (WebRTC offers, answers, and ICE candidates) necessary for peers to find each other. **No file data passes through this server.**

2. **Connection Phase**: Peers use the exchanged metadata to establish a direct, encrypted data channel (P2P).

3. **Transfer Phase**: Once connected, the sending peer chunks the file into 65KB segments and transmits them directly over the secure WebRTC channel to the receiver.

4. **Reconstruction Phase**: The receiving peer reassembles the chunks and verifies integrity before presenting the complete file to the user.

### 🎓 Thesis Details

- **Student Name:** Mohamed Ali Belmokhtaria  
- **Graduation Year:** 2025  
- **Supervisor:** Ms. Fang Yuan
