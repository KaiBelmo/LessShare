<template>
  <div class="min-h-screen bg-gray-900 text-cyan-100 font-mono overflow-hidden">
    <div class="scanlines"></div>
    <div class="container mx-auto px-4 py-8 relative z-10">
      <!-- Header Section -->
      <div
        class="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 border-b border-cyan-500/20 pb-4"
      >
        <div>
          <h1 class="text-3xl font-bold neon-text">
            LESSSHARE
            <span class="text-sm ml-4 text-cyan-300"
              >/ DIRECT DATA TRANSFER</span
            >
          </h1>
          <div class="flex items-center space-x-3 mt-2">
            <div
              class="h-3 w-3 rounded-full"
              :class="{
                'bg-red-500 animate-pulse': !isConnected,
                'bg-green-500': isConnected,
              }"
            ></div>
            <span class="text-sm">
              {{
                isConnected
                  ? "PEER CONNECTIONS: ESTABLISHED"
                  : "CONNECTION: INITIALIZING"
              }}
            </span>
          </div>
        </div>

        <div
          class="text-xs bg-gray-800/50 px-3 py-1 rounded-full border border-cyan-500/30 text-cyan-300 mt-2 md:mt-0"
        >
          {{
            creatorUsername
              ? `${creatorUsername.toUpperCase()}'S ROOM`
              : "LOADING ROOM..."
          }}
          ({{ remotePeers.length }} peers) | USER:
          {{ userStore.user?.username || "UNKNOWN" }}
        </div>
      </div>

      <!-- Connection Progress Bar -->
      <div class="mb-6 bg-gray-900/50 p-3 rounded border border-cyan-500/20">
        <div class="h-1 w-full bg-gray-800 rounded-full overflow-hidden">
          <div
            class="h-full bg-gradient-to-r from-cyan-500 to-purple-500 transition-all duration-1000"
            :style="{ width: connectionProgress + '%' }"
          ></div>
        </div>
      </div>

      <!-- Main Content Area -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Left Column - File Transfer -->
        <div class="lg:col-span-2 space-y-6">
          <!-- File Upload Section -->
          <div
            class="border border-cyan-500/30 rounded-lg p-5 bg-gray-900/50 backdrop-blur-sm"
          >
            <h2 class="text-xl font-bold text-cyan-300 mb-4 flex items-center">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                class="h-5 w-5 mr-2"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
                />
              </svg>
              UPLOAD FILES
            </h2>
            <div
              @dragover.prevent="dragOver = true"
              @dragleave="dragOver = false"
              @drop.prevent="handleDrop"
              class="border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-colors"
              :class="{
                'border-cyan-500 bg-cyan-900/10': dragOver,
                'border-cyan-500/30': !dragOver,
              }"
            >
              <input
                type="file"
                id="fileInput"
                @change="onFileChange"
                class="hidden"
                multiple
              />
              <label for="fileInput" class="cursor-pointer">
                <div
                  class="flex flex-col items-center justify-center space-y-2"
                >
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    class="h-12 w-12 text-cyan-400"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
                    />
                  </svg>
                  <p class="text-lg font-medium">SELECT FILES</p>
                  <p class="text-sm text-cyan-400/80">
                    DRAG & DROP OR CLICK TO BROWSE (MULTIPLE FILES SUPPORTED)
                  </p>
                </div>
              </label>
            </div>

            <!-- Selected Files List -->
            <div v-if="files.length" class="mt-6">
              <div class="max-h-60 overflow-y-auto pr-2 space-y-3">
                <div
                  v-for="(file, index) in files"
                  :key="index"
                  class="bg-gray-800/50 p-3 rounded border border-cyan-500/20 flex items-center justify-between"
                >
                  <div class="flex-1 min-w-0">
                    <div class="flex justify-between items-center mb-1">
                      <span class="text-sm text-cyan-300 truncate">{{
                        file.name
                      }}</span>
                      <span
                        class="text-xs bg-cyan-900/50 px-2 py-1 rounded whitespace-nowrap ml-2"
                      >
                        {{ formatFileSize(file.size) }}
                      </span>
                    </div>
                    <div
                      v-if="
                        uploadProgress[index] > 0 && uploadProgress[index] < 100
                      "
                      class="mt-2"
                    >
                      <div
                        class="flex justify-between text-xs text-cyan-400 mb-1"
                      >
                        <span>TRANSFERRING:</span>
                        <span>{{ uploadProgress[index] }}%</span>
                      </div>
                      <div
                        class="h-1.5 w-full bg-gray-800 rounded-full overflow-hidden"
                      >
                        <div
                          class="h-full bg-gradient-to-r from-cyan-500 to-purple-500"
                          :style="{ width: uploadProgress[index] + '%' }"
                        ></div>
                      </div>
                    </div>
                  </div>
                  <button
                    @click="removeFile(index)"
                    class="ml-3 p-1.5 bg-red-900/50 hover:bg-red-800/70 text-red-300 rounded transition"
                    title="Remove file"
                    :disabled="isSending"
                  >
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      class="h-4 w-4"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                    >
                      <path
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                      />
                    </svg>
                  </button>
                </div>
              </div>
              <button
                @click="shareFiles"
                class="w-full mt-4 py-2 px-4 bg-cyan-900/50 hover:bg-cyan-800/70 text-cyan-300 rounded transition flex items-center justify-center space-x-2 disabled:bg-gray-700/50 disabled:text-gray-500 disabled:cursor-not-allowed disabled:hover:bg-gray-700/50"
                :disabled="!files.length || !isConnected || isSending"
              >
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  class="h-5 w-5"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"
                  />
                </svg>
                <span>INITIATE TRANSFER</span>
              </button>
            </div>
          </div>

          <!-- Incoming Files Section -->
          <div
            class="border border-cyan-500/30 rounded-lg p-5 bg-gray-900/50 backdrop-blur-sm"
          >
            <h2 class="text-xl font-bold text-cyan-300 mb-4 flex items-center">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                class="h-5 w-5 mr-2"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"
                />
              </svg>
              INCOMING FILES
            </h2>
            <div
              v-if="receivedFiles.length"
              class="max-h-60 overflow-y-auto pr-2 space-y-3"
            >
              <div
                v-for="(fileData, index) in receivedFiles"
                :key="index"
                class="bg-gray-800/50 p-3 rounded border border-cyan-500/20"
              >
                <div class="flex justify-between items-center mb-1">
                  <span class="text-sm font-medium text-cyan-200 truncate">{{
                    fileData.fileName
                  }}</span>
                  <span
                    class="text-xs bg-purple-900/50 px-2 py-1 rounded whitespace-nowrap ml-2"
                  >
                    {{ formatFileSize(fileData.fileSize) }}
                  </span>
                </div>
                <div
                  v-if="
                    downloadProgress[index] > 0 && downloadProgress[index] < 100
                  "
                  class="mt-2"
                >
                  <div
                    class="flex justify-between text-xs text-purple-400 mb-1"
                  >
                    <span>RECEIVING:</span>
                    <span>{{ downloadProgress[index] }}%</span>
                  </div>
                  <div
                    class="h-1.5 w-full bg-gray-800 rounded-full overflow-hidden"
                  >
                    <div
                      class="h-full bg-gradient-to-r from-purple-500 to-cyan-500"
                      :style="{ width: downloadProgress[index] + '%' }"
                    ></div>
                  </div>
                </div>
                <button
                  @click="downloadReceivedFile(index)"
                  class="w-full mt-3 py-2 px-4 bg-purple-900/50 hover:bg-purple-800/70 text-purple-300 rounded transition flex items-center justify-center space-x-2 text-sm"
                >
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    class="h-4 w-4"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"
                    />
                  </svg>
                  <span>DOWNLOAD FILE</span>
                </button>
              </div>
            </div>
            <div
              v-else
              class="text-center py-8 text-cyan-400/50 border border-dashed border-cyan-500/20 rounded-lg"
            >
              <p>WAITING FOR INCOMING TRANSFER...</p>
              <p class="text-xs mt-2">CONNECTION ACTIVE</p>
            </div>
          </div>
        </div>

        <!-- Right Column - Chat and History -->
        <div class="space-y-6">
          <!-- Chat Section -->
          <div
            class="border border-cyan-500/30 rounded-lg p-5 bg-gray-900/50 backdrop-blur-sm"
          >
            <h2 class="text-xl font-bold text-cyan-300 mb-4 flex items-center">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                class="h-5 w-5 mr-2"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"
                />
              </svg>
              CHAT ROOM
            </h2>
            <div class="h-64 flex flex-col">
              <div
                class="flex-1 overflow-y-auto pr-2 space-y-2 mb-3"
                ref="chatContainer"
              >
                <div
                  v-for="message in messages"
                  :key="message.id"
                  class="bg-gray-800/50 p-3 rounded border border-cyan-500/20 hover:shadow-[0_0_5px_rgba(0,255,255,0.3)] transition-shadow"
                  :class="{
                    'bg-cyan-900/20 border-cyan-500/50':
                      message.senderId === userStore.user?.id,
                  }"
                >
                  <div class="flex justify-between items-center mb-1">
                    <span class="text-sm font-medium text-cyan-300">{{
                      message.senderUsername
                    }}</span>
                    <span class="text-xs text-cyan-400/80">{{
                      formatDate(message.sentAt)
                    }}</span>
                  </div>
                  <p class="text-sm break-words">{{ message.content }}</p>
                </div>
                <div
                  v-if="!messages.length"
                  class="text-center py-8 text-cyan-400/50 border border-dashed border-cyan-500/20 rounded-lg"
                >
                  <p>NO MESSAGES YET</p>
                </div>
              </div>
              <form
                @submit.prevent="sendMessage"
                class="flex items-center space-x-2"
              >
                <input
                  v-model="newMessage"
                  type="text"
                  placeholder="TYPE MESSAGE..."
                  class="flex-1 bg-gray-800/50 text-cyan-100 placeholder-cyan-400/50 rounded p-2 border border-cyan-500/30 focus:outline-none focus:border-cyan-500 text-sm"
                  :disabled="!isConnected || isSendingMessage"
                  maxlength="1000"
                />
                <button
                  type="submit"
                  class="py-2 px-3 bg-cyan-900/50 hover:bg-cyan-800/70 text-cyan-300 rounded transition flex items-center space-x-1 disabled:bg-gray-700/50 disabled:text-gray-500 disabled:cursor-not-allowed text-sm"
                  :disabled="
                    !isConnected || isSendingMessage || !newMessage.trim()
                  "
                >
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    class="h-4 w-4"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"
                    />
                  </svg>
                  <span>SEND</span>
                </button>
              </form>
            </div>
          </div>

          <!-- File History Section -->
          <div
            class="border border-cyan-500/30 rounded-lg p-5 bg-gray-900/50 backdrop-blur-sm max-h-80"
          >
            <h2 class="text-xl font-bold text-cyan-300 mb-4 flex items-center">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                class="h-5 w-5 mr-2"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                />
              </svg>
              FILE HISTORY
            </h2>
            <div
              v-if="fileHistory.length"
              class="max-h-60 overflow-y-auto pr-2 space-y-3"
            >
              <div
                v-for="file in fileHistory"
                :key="file.sharedAt"
                class="bg-gray-800/50 p-3 rounded border border-cyan-500/20 hover:bg-gray-800/70 transition-colors"
              >
                <p class="text-sm text-cyan-300 truncate">
                  {{ file.fileName }}
                  <span class="text-cyan-400/80"
                    >({{ formatFileSize(file.fileSize) }})</span
                  >
                </p>
                <div class="flex justify-between items-center mt-1">
                  <p class="text-xs text-cyan-400/80">
                    From: {{ file.senderPeerId }}
                  </p>
                  <p class="text-xs text-cyan-400/80">
                    {{ formatDate(file.sharedAt) }}
                  </p>
                </div>
              </div>
            </div>
            <div
              v-else
              class="text-center py-8 text-cyan-400/50 border border-dashed border-cyan-500/20 rounded-lg"
            >
              <p>NO FILES SHARED YET</p>
            </div>
          </div>
        </div>
      </div>

      <!-- Connection Debug (Collapsible) -->
      <div v-if="peerConnections.length" class="mt-6">
        <details
          class="bg-gray-900/50 p-3 rounded border border-cyan-500/20 text-xs text-cyan-300"
        >
          <summary class="text-sm font-bold cursor-pointer">
            Connection Debug
          </summary>
          <div class="mt-2 space-y-1">
            <p>Local Peer: {{ localPeerId }}</p>
            <p>Connected Peers: {{ peerConnections.length }}</p>
            <p v-for="conn in peerConnections" :key="conn.peerId">
              Peer {{ conn.peerId }}: ICE={{ conn.pc.iceConnectionState }},
              DataChannel={{ dataChannels[conn.peerId]?.readyState || "none" }}
            </p>
          </div>
        </details>
      </div>

      <!-- Toast Notification -->
      <div
        v-if="toastMessage"
        class="fixed bottom-4 right-4 bg-gray-800/90 text-cyan-300 px-4 py-2 rounded border border-cyan-500/30 text-sm shadow-[0_0_10px_rgba(0,255,255,0.5)] z-20"
      >
        {{ toastMessage }}
      </div>
    </div>
  </div>
</template>

<style scoped>
.scanlines {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: linear-gradient(
    to bottom,
    rgba(0, 255, 255, 0.02) 50%,
    rgba(0, 0, 0, 0.1) 50%
  );
  background-size: 100% 4px;
  pointer-events: none;
  z-index: 10;
}

.neon-text {
  text-shadow: 0 0 5px rgba(0, 255, 255, 0.5), 0 0 10px rgba(0, 255, 255, 0.3);
}
</style>
<style scoped>
.scanlines {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: linear-gradient(
    to bottom,
    rgba(0, 255, 255, 0.02) 50%,
    rgba(0, 0, 0, 0.1) 50%
  );
  background-size: 100% 4px;
  pointer-events: none;
  z-index: 10;
}

.neon-text {
  text-shadow: 0 0 5px rgba(0, 255, 255, 0.5), 0 0 10px rgba(0, 255, 255, 0.3);
}
</style>

<script setup>
import { ref, onMounted, onBeforeUnmount, nextTick } from "vue";
import { useRoute, useRouter } from "vue-router";
import { io } from "socket.io-client";
import { useUserStore } from "@/stores/userStore";

const route = useRoute();
const router = useRouter(); // Added for redirection
const userStore = useUserStore();
const roomId = ref(route.params.id);
const toastMessage = ref(null);

const isConnected = ref(false);
const connectionProgress = ref(0);
const isSending = ref(false);
const isSendingMessage = ref(false);

const fileHistory = ref([]);
const messages = ref([]);
const newMessage = ref("");
const chatContainer = ref(null);

const files = ref([]);
const dragOver = ref(false);
const uploadProgress = ref([]);
const downloadProgress = ref([]);
let receivedBytes = [];

const creatorPeerId = ref(null);
const creatorUsername = ref(null); // Added to store creator's username

const receivedFiles = ref([]);
const peerConnections = ref([]);
const dataChannels = ref({});
const localPeerId = ref(null);
const remotePeers = ref([]);
const MAXIMUM_MESSAGE_SIZE = 65535;
const END_OF_FILE_MESSAGE = "EOF";

const socket = io(`${import.meta.env.VITE_APP_API_URL}`, {
  reconnectionAttempts: 5,
  reconnectionDelay: 1000,
  autoConnect: true,
  // Auth token will be sent in the 'auth' event
});

const simulateConnectionProgress = () => {
  const interval = setInterval(() => {
    if (connectionProgress.value < 90) {
      connectionProgress.value += 10;
    } else {
      clearInterval(interval);
    }
  }, 300);
};

async function addPeerToRoom(peerId) {
  try {
    const response = await fetch(
      `${import.meta.env.VITE_APP_API_URL}/api/rooms/${roomId.value}/peers`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${userStore.token}`,
        },
        body: JSON.stringify({ peerId }),
      }
    );
    const data = await response.json();
    if (!response.ok) {
      console.error(
        `Failed to add peer ${peerId} to room ${roomId.value}: ${data.error}`
      );
    } else {
      console.log(`Peer ${peerId} added to room ${roomId.value} in database`);
    }
  } catch (err) {
    console.error(
      `Error adding peer ${peerId} to room ${roomId.value}: ${err.message}`
    );
  }
}

async function fetchRoomDetails() {
  try {
    const response = await fetch(
      `${import.meta.env.VITE_APP_API_URL}/api/rooms/${roomId.value}`,
      {
        headers: { Authorization: `Bearer ${userStore.token}` },
      }
    );
    const data = await response.json();
    
    if (response.ok) {
      fileHistory.value = data.files || [];
      messages.value = data.messages || [];
      
      // Get creator username from the first message (if available)
      // Or use a default since backend doesn't send creator username directly
      creatorUsername.value = data.messages[0]?.senderUsername || "UNKNOWN";
      
      // You might also want to store other data
      peers.value = data.peers || [];
      fileCount.value = data.fileCount || 0;
      
      console.log("-------------------------------------");
      console.log("Full room data:", data);
      console.log("Files count:", data.files?.length);
      console.log("Messages count:", data.messages?.length);
      console.log("Peers count:", data.peers?.length);
      console.log("-------------------------------------");
      
      // Scroll to bottom of chat after loading messages
      nextTick(() => scrollToBottom());
    } else {
      console.error("Failed to fetch room:", data.error);
      toastMessage.value = "Failed to load room data";
      setTimeout(() => {
        toastMessage.value = null;
      }, 3000);
    }
  } catch (err) {
    console.error("Error fetching room:", err);
    toastMessage.value = "Failed to load room data";
    setTimeout(() => {
      toastMessage.value = null;
    }, 3000);
  }
}

function scrollToBottom() {
  if (chatContainer.value) {
    chatContainer.value.scrollTop = chatContainer.value.scrollHeight;
  }
}

async function sendMessage() {
  if (!newMessage.value.trim()) return;
  if (newMessage.value.length > 1000) {
    toastMessage.value = "Message too long (max 1000 characters)";
    setTimeout(() => {
      toastMessage.value = null;
    }, 3000);
    return;
  }

  isSendingMessage.value = true;
  socket.emit(
    "chat-message",
    { roomId: roomId.value, content: newMessage.value },
    (response) => {
      isSendingMessage.value = false;
      if (response.success) {
        newMessage.value = "";
      } else {
        console.error("Failed to send message:", response.error);
        toastMessage.value = response.error || "Failed to send message";
        setTimeout(() => {
          toastMessage.value = null;
        }, 3000);
      }
    }
  );
}

function formatDate(date) {
  return new Date(date).toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: true,
  });
}

function createPeerConnection(peerId) {
  const config = {
    iceServers: [
      { urls: "stun:stun.l.google.com:19302" },
      { urls: "stun:stun1.l.google.com:19302" },
      { urls: "stun:stun2.l.google.com:19302" },
      { urls: "stun:stun3.l.google.com:19302" },
      { urls: "stun:stun4.l.google.com:19302" }
    ],
  };
  console.log(`Creating peer connection for ${peerId}`);
  const pc = new RTCPeerConnection(config);
  pc.onicecandidate = (event) => handleIceCandidate(event, peerId);
  pc.ondatachannel = (event) => {
    console.log(`Received data channel from ${peerId}`);
    setupDataChannel(event.channel, peerId);
  };
  pc.oniceconnectionstatechange = () => {
    console.log(`ICE connection state for ${peerId}: ${pc.iceConnectionState}`);
    if (
      pc.iceConnectionState === "failed" ||
      pc.iceConnectionState === "disconnected"
    ) {
      console.error(
        `ICE connection issue for ${peerId}: ${pc.iceConnectionState}`
      );
      pc.restartIce();
    }
    if (
      pc.iceConnectionState === "connected" ||
      pc.iceConnectionState === "completed"
    ) {
      console.log(`ICE connection established with ${peerId}`);
    }
    checkConnectionStatus();
  };
  pc.onicecandidateerror = (event) => {
    console.error(`ICE candidate error for ${peerId}:`, event);
  };

  const datachannel = pc.createDataChannel("filetransfer");
  setupDataChannel(datachannel, peerId);

  peerConnections.value.push({ peerId, pc });
  addPeerToRoom(peerId);

  return pc;
}

function handleIceCandidate(event, toPeerId) {
  if (event.candidate) {
    console.log(`Sending ICE candidate to ${toPeerId}`);
    socket.emit("signal", {
      to: toPeerId,
      from: localPeerId.value,
      data: {
        type: "candidate",
        candidate: event.candidate.candidate,
        sdpMLineIndex: event.candidate.sdpMLineIndex,
      },
    });
  }
}

async function doCall(toPeerId) {
  const pc = peerConnections.value.find((p) => p.peerId === toPeerId)?.pc;
  if (!pc) {
    console.error(`No peer connection found for ${toPeerId}`);
    return;
  }

  try {
    console.log(`Creating offer for ${toPeerId}`);
    const offer = await pc.createOffer();
    console.log(`Offer created for ${toPeerId}:`, offer);
    await pc.setLocalDescription(offer);
    console.log(`Local description set for ${toPeerId}`);
    if (socket.connected) {
      socket.emit("signal", {
        to: toPeerId,
        from: localPeerId.value,
        data: offer,
      });
      console.log(`Offer sent to ${toPeerId}`);
    } else {
      console.error(`Socket not connected, cannot send offer to ${toPeerId}`);
    }
  } catch (error) {
    console.error(`Error in doCall for ${toPeerId}:`, error);
  }
}

async function doAnswer(fromPeerId) {
  const pc = peerConnections.value.find((p) => p.peerId === fromPeerId)?.pc;
  if (!pc) {
    console.error(`No peer connection found for ${fromPeerId}`);
    return;
  }

  try {
    console.log(`Creating answer for ${fromPeerId}`);
    const answer = await pc.createAnswer();
    console.log(`Answer created for ${fromPeerId}`);
    await pc.setLocalDescription(answer);
    console.log(`Local description set for ${fromPeerId}`);
    socket.emit("signal", {
      to: fromPeerId,
      from: localPeerId.value,
      data: answer,
    });
    console.log(`Answer sent to ${fromPeerId}`);
  } catch (error) {
    console.error(`Error in doAnswer for ${fromPeerId}:`, error);
  }
}

function setupDataChannel(channel, peerId) {
  dataChannels.value[peerId] = channel;
  console.log(
    `DataChannel created for ${peerId}, initial state: ${channel.readyState}`
  );
  channel.onopen = () => {
    console.log(
      `DataChannel open with ${peerId}, state: ${channel.readyState}`
    );
    checkConnectionStatus();
  };
  channel.onmessage = (event) => handleDataChannelMessage(event, peerId);
  channel.onclose = () => {
    console.log(
      `DataChannel closed with ${peerId}, state: ${channel.readyState}`
    );
    checkConnectionStatus();
  };
  channel.onerror = (error) => {
    console.error(`DataChannel error with ${peerId}:`, error);
  };
}

function handleDataChannelMessage(event, peerId) {
  const data = event.data;

  try {
    const potentialMetadata = JSON.parse(data);
    if (potentialMetadata.action === "metadata") {
      receivedFiles.value.push({
        buffers: [],
        fileName: potentialMetadata.fileName,
        fileType: potentialMetadata.fileType,
        fileSize: potentialMetadata.fileSize,
        canDownload: false,
      });
      receivedBytes.push(0);
      downloadProgress.value.push(0);
      console.log(`Received metadata from ${peerId}:`, potentialMetadata);
      return;
    }
  } catch (e) {
    // Not JSON, treat as binary data
  }

  if (data !== END_OF_FILE_MESSAGE) {
    const lastFileIndex = receivedFiles.value.length - 1;
    if (lastFileIndex >= 0) {
      receivedFiles.value[lastFileIndex].buffers.push(data);
      receivedBytes[lastFileIndex] += data.byteLength || data.size || 0;
      downloadProgress.value[lastFileIndex] = Math.round(
        (receivedBytes[lastFileIndex] /
          receivedFiles.value[lastFileIndex].fileSize) *
          100
      );
    }
  } else {
    const lastFileIndex = receivedFiles.value.length - 1;
    if (lastFileIndex >= 0) {
      console.log(`File transfer complete from ${peerId}`);
      receivedFiles.value[lastFileIndex].canDownload = true;
      toastMessage.value = `File "${receivedFiles.value[lastFileIndex].fileName}" received successfully!`;
      setTimeout(() => {
        toastMessage.value = null;
      }, 3000);
    }
  }
}

function checkConnectionStatus() {
  const hasPeers = remotePeers.value.length > 0;
  const hasConnections = peerConnections.value.length > 0;
  const anyConnected = peerConnections.value.some(
    ({ pc }) =>
      pc.iceConnectionState === "connected" ||
      pc.iceConnectionState === "completed"
  );
  const anyChannelsOpen = Object.values(dataChannels.value).some(
    (channel) => channel.readyState === "open"
  );

  isConnected.value =
    hasPeers && (hasConnections || anyConnected || anyChannelsOpen);
  if (isConnected.value) {
    connectionProgress.value = 100;
  } else {
    connectionProgress.value = Math.min(90, remotePeers.value.length * 30);
  }
  console.log(
    `Connection status: isConnected=${isConnected.value}, peerConnections=${peerConnections.value.length}, remotePeers=${remotePeers.value.length}, anyConnected=${anyConnected}, anyChannelsOpen=${anyChannelsOpen}`
  );
}

function handleDrop(event) {
  dragOver.value = false;
  const droppedFiles = Array.from(event.dataTransfer.files);
  if (droppedFiles.length) {
    files.value = [...files.value, ...droppedFiles];
    uploadProgress.value = [
      ...uploadProgress.value,
      ...new Array(droppedFiles.length).fill(0),
    ];
  }
}

function onFileChange(event) {
  const selectedFiles = Array.from(event.target.files);
  if (selectedFiles.length) {
    files.value = [...files.value, ...selectedFiles];
    uploadProgress.value = [
      ...uploadProgress.value,
      ...new Array(selectedFiles.length).fill(0),
    ];
    event.target.value = ""; // Clear input for re-selection
  }
}

function removeFile(index) {
  files.value.splice(index, 1);
  uploadProgress.value.splice(index, 1);
  if (!files.value.length) {
    const fileInput = document.getElementById("fileInput");
    if (fileInput) fileInput.value = "";
  }
}

async function shareFiles() {
  if (!files.value.length) {
    toastMessage.value = "No files selected";
    setTimeout(() => {
      toastMessage.value = null;
    }, 3000);
    return;
  }

  if (!isConnected.value || remotePeers.value.length === 0) {
    toastMessage.value = "No peers connected to receive files";
    setTimeout(() => {
      toastMessage.value = null;
    }, 3000);
    return;
  }

  isSending.value = true;

  try {
    for (let i = 0; i < files.value.length; i++) {
      const file = files.value[i];
      const totalSize = file.size;
      let sentBytes = 0;

      const metadata = {
        action: "metadata",
        fileName: file.name,
        fileType: file.type,
        fileSize: file.size,
      };
      // Add to fileHistory for sender
      fileHistory.value.push({
        fileName: metadata.fileName,
        fileType: metadata.fileType,
        fileSize: metadata.fileSize,
        senderPeerId: localPeerId.value, // Sender's peerId
        sharedAt: new Date(),
      });
      socket.emit("file-metadata", { roomId: roomId.value, metadata });

      const buffer = await file.arrayBuffer();
      const chunkSize = 16 * 1024;

      await new Promise((resolve) => {
        async function sendChunk(j) {
          if (j >= buffer.byteLength) {
            socket.emit("file-complete", roomId.value);
            resolve();
            return;
          }

          const chunk = buffer.slice(
            j,
            Math.min(j + chunkSize, buffer.byteLength)
          );
          socket.emit("file-chunk", { roomId: roomId.value, chunk });

          sentBytes += chunk.byteLength;
          uploadProgress.value[i] = Math.round((sentBytes / totalSize) * 100);
          setTimeout(() => sendChunk(j + chunkSize), 0);
        }
        sendChunk(0);
      });

      toastMessage.value = `File "${file.name}" sent successfully!`;
      setTimeout(() => {
        toastMessage.value = null;
      }, 3000);
    }

    files.value = [];
    uploadProgress.value = [];
    const fileInput = document.getElementById("fileInput");
    if (fileInput) fileInput.value = "";
  } catch (err) {
    console.error("Transfer error:", err);
    toastMessage.value = "Failed to send files";
    setTimeout(() => {
      toastMessage.value = null;
    }, 3000);
  } finally {
    isSending.value = false;
  }
}

function downloadReceivedFile(index) {
  const fileData = receivedFiles.value[index];
  if (fileData.buffers.length > 0) {
    const arrayBuffer = fileData.buffers.reduce((acc, curr) => {
      const tmp = new Uint8Array(acc.byteLength + curr.byteLength);
      tmp.set(new Uint8Array(acc), 0);
      tmp.set(new Uint8Array(curr), acc.byteLength);
      return tmp;
    }, new Uint8Array());

    const blob = new Blob([arrayBuffer], {
      type: fileData.fileType,
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = fileData.fileName || `received_file_${index}`;
    document.body.appendChild(a);
    a.click();

    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      receivedFiles.value.splice(index, 1);
      downloadProgress.value.splice(index, 1);
      receivedBytes.splice(index, 1);
    }, 100);
  }
}

function formatFileSize(bytes) {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

onMounted(() => {
  userStore.initialize();
  if (!userStore.isAuthenticated) {
    // Redirect to username page with roomId as query parameter
    router.push(`/username?roomId=${roomId.value}`);
    return;
  }
  fetchRoomDetails();
  console.log(`Connecting to room ${roomId.value}`);
  simulateConnectionProgress();

  // Authenticate socket connection
  socket.emit("auth", { token: userStore.token }, (response) => {
    if (!response.success) {
      console.error("Socket authentication failed:", response.error);
      toastMessage.value = "Authentication failed";
      setTimeout(() => {
        toastMessage.value = null;
      }, 3000);
      router.push(`/username?roomId=${roomId.value}`);
    } else {
      console.log("Socket authenticated successfully");
    }
  });
  socket.on("connect", () => {
    console.log("Socket connected, joining room");
    socket.emit("join-room", roomId.value, (response) => {
      if (response.success) {
        localPeerId.value = response.peerId;
        remotePeers.value = response.peers;
        creatorPeerId.value = response.creatorPeerId;
        console.log(
          `Joined room ${roomId.value} as peer ${localPeerId.value}, creator: ${creatorPeerId.value}`
        );
        response.peers.forEach((peerId) => {
          if (!peerConnections.value.find((p) => p.peerId === peerId)) {
            const pc = createPeerConnection(peerId);
            if (localPeerId.value < peerId) {
              doCall(peerId);
            }
          }
        });
        checkConnectionStatus();
      } else {
        console.error("Failed to join room:", response.error);
        toastMessage.value = "Failed to join room";
        setTimeout(() => {
          toastMessage.value = null;
        }, 3000);
        router.push(`/username?roomId=${roomId.value}`);
      }
    });
  });

  socket.on("connect_error", (error) => {
    console.error("Socket connection error:", error);
    toastMessage.value = "Connection error";
    setTimeout(() => {
      toastMessage.value = null;
    }, 3000);
  });

  socket.on("reconnect", (attempt) => {
    console.log(`Reconnected to server after ${attempt} attempts`);
    // Re-authenticate on reconnect
    socket.emit("auth", { token: userStore.token }, (response) => {
      if (!response.success) {
        console.error("Socket re-authentication failed:", response.error);
        toastMessage.value = "Authentication failed";
        setTimeout(() => {
          toastMessage.value = null;
        }, 3000);
        router.push(`/username?roomId=${roomId.value}`);
      }
    });
  });
  socket.on("peer-connected", (peerId) => {
    console.log(`Peer ${peerId} connected to room`);
    if (!remotePeers.value.includes(peerId)) {
      remotePeers.value.push(peerId);
      console.log(
        `Added peer ${peerId} to remotePeers, total peers: ${remotePeers.value.length}`
      );
      if (!peerConnections.value.find((p) => p.peerId === peerId)) {
        const pc = createPeerConnection(peerId);
        if (localPeerId.value < peerId) {
          doCall(peerId);
        }
      }
      checkConnectionStatus();
    }
  });

  socket.on("peer-disconnected", (peerId) => {
    console.log(`Peer ${peerId} disconnected`);
    remotePeers.value = remotePeers.value.filter((id) => id !== peerId);
    peerConnections.value = peerConnections.value.filter((p) => {
      if (p.peerId === peerId) {
        p.pc.close();
        delete dataChannels.value[peerId];
        return false;
      }
      return true;
    });
    checkConnectionStatus();
  });

  socket.on("signal", async ({ from, data }) => {
    console.log(`Received signal from ${from}: ${data.type}`);
    let pc = peerConnections.value.find((p) => p.peerId === from)?.pc;

    if (!pc) {
      console.log(`No existing connection for ${from}, creating new one`);
      pc = createPeerConnection(from);
      if (!remotePeers.value.includes(from)) {
        remotePeers.value.push(from);
        console.log(
          `Added peer ${from} to remotePeers, total peers: ${remotePeers.value.length}`
        );
      }
      console.log(
        `Peer connection created for ${from}, total connections: ${peerConnections.value.length}`
      );
    }

    try {
      if (data.type === "offer") {
        console.log(
          `Setting remote description (offer) from ${from}:`,
          data.sdp.substring(0, 50) + "..."
        );
        await pc.setRemoteDescription(new RTCSessionDescription(data));
        console.log(`Offer set for ${from}, creating answer`);
        await doAnswer(from);
      } else if (data.type === "answer") {
        console.log(
          `Setting remote description (answer) from ${from}:`,
          data.sdp.substring(0, 50) + "..."
        );
        await pc.setRemoteDescription(new RTCSessionDescription(data));
        console.log(`Answer set for ${from}`);
      } else if (data.type === "candidate") {
        console.log(
          `Adding ICE candidate from ${from}:`,
          data.candidate.substring(0, 50) + "..."
        );
        await pc.addIceCandidate(
          new RTCIceCandidate({
            candidate: data.candidate,
            sdpMLineIndex: data.sdpMLineIndex,
          })
        );
        console.log(`ICE candidate added for ${from}`);
      }
      checkConnectionStatus();
    } catch (error) {
      console.error(`Error handling signal from ${from}:`, error);
    }
  });

  socket.on("file-metadata", (metadata, senderPeerId) => {
    console.log("Received file metadata:", metadata, "from", senderPeerId);
    // Add to fileHistory for all peers
    fileHistory.value.push({
      fileName: metadata.fileName,
      fileType: metadata.fileType,
      fileSize: metadata.fileSize,
      senderPeerId: senderPeerId,
      sharedAt: new Date(),
    });
    // Only add to receivedFiles if not the sender
    if (senderPeerId !== localPeerId.value) {
      receivedFiles.value.push({
        buffers: [],
        fileName: metadata.fileName,
        fileType: metadata.fileType,
        fileSize: metadata.fileSize,
        canDownload: false,
      });
      receivedBytes.push(0);
      downloadProgress.value.push(0);
    }
  });

  socket.on("file-chunk", (chunk) => {
    const lastFileIndex = receivedFiles.value.length - 1;
    if (lastFileIndex >= 0) {
      receivedFiles.value[lastFileIndex].buffers.push(chunk);
      receivedBytes[lastFileIndex] += chunk.byteLength || chunk.size || 0;
      downloadProgress.value[lastFileIndex] = Math.round(
        (receivedBytes[lastFileIndex] /
          receivedFiles.value[lastFileIndex].fileSize) *
          100
      );
    }
  });

  socket.on("file-complete", () => {
    const lastFileIndex = receivedFiles.value.length - 1;
    if (lastFileIndex >= 0) {
      console.log("File transfer complete");
      receivedFiles.value[lastFileIndex].canDownload = true;
      toastMessage.value = `File "${receivedFiles.value[lastFileIndex].fileName}" received successfully!`;
      setTimeout(() => {
        toastMessage.value = null;
      }, 3000);
    }
  });

  socket.on("chat-message", (message) => {
    console.log("Received chat message:", message);
    messages.value.push(message);
    nextTick(() => scrollToBottom());
  });
});

onBeforeUnmount(() => {
  peerConnections.value.forEach(({ pc }) => pc.close());
  socket.emit("leave-room", roomId.value);
  socket.disconnect();
});
</script>

<style>
.scanlines {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: linear-gradient(
    to bottom,
    transparent 0%,
    rgba(0, 255, 255, 0.05) 50%,
    transparent 100%
  );
  background-size: 100% 4px;
  pointer-events: none;
  z-index: 1;
}

.neon-text {
  text-shadow: 0 0 5px #0ff, 0 0 10px #0ff, 0 0 15px #0ff;
}

button:hover {
  box-shadow: 0 0 10px rgba(0, 255, 255, 0.5);
  transition: box-shadow 0.3s ease;
}

body {
  font-family: "Courier New", monospace;
}

::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}

::-webkit-scrollbar-track {
  background: rgba(0, 0, 0, 0.1);
}

::-webkit-scrollbar-thumb {
  background: rgba(0, 255, 255, 0.3);
  border-radius: 3px;
}

::-webkit-scrollbar-thumb:hover {
  background: rgba(0, 255, 255, 0.5);
}

button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
</style>
