<template>
  <div class="container mx-auto px-4 py-12">
    <div class="flex justify-between items-center mb-12">
      <h1 class="text-3xl font-bold text-cyan-400">
        ACTIVE SESSIONS FOR <span class="bg-purple-900/50 text-purple-300 rounded px-2 py-1">{{ userStore.username }}</span>
      </h1>
      <div class="flex space-x-4">
        <NeonButton label="+ NEW TRANSFER ROOM" @click="createNewRoom" />
        <button 
          @click="confirmDestroyAccount"
          class="px-4 py-2 border border-red-500/30 text-red-400 hover:bg-red-900/20 transition rounded-lg"
        >
          DESTROY ACCOUNT
        </button>
      </div>
    </div>
    
    <div v-if="loading" class="text-center py-12">
      <p class="text-cyan-400 animate-pulse">LOADING SESSION DATA...</p>
    </div>
    
    <div v-else-if="error" class="text-center py-12 border border-red-500/30 rounded-lg bg-red-900/20">
      <p class="text-red-400 mb-4">{{ error }}</p>
      <NeonButton label="RETRY" @click="fetchRooms" />
    </div>
    
    <div v-else>
      <div v-if="rooms.length === 0" class="text-center py-12 border border-dashed border-cyan-500/30 rounded-lg">
        <p class="text-cyan-300 mb-4">NO ACTIVE TRANSFER ROOMS FOUND</p>
        <NeonButton label="INITIATE FIRST TRANSFER" @click="createNewRoom" />
      </div>
      
      <div v-else class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <div 
          v-for="room in rooms" 
          :key="room.id"
          class="border border-cyan-500/20 hover:border-cyan-500/50 p-6 rounded-lg transition-all duration-300 hover:bg-gray-800/30 cursor-pointer"
          @click="joinRoom(room.roomId)"
        >
          <div class="flex justify-between items-start mb-4">
            <h3 class="text-xl font-bold text-cyan-300">{{ room.name }}</h3>
            <span class="text-xs px-2 py-1 bg-red-600 bg-opacity-30 text-white rounded">
              {{ room.status }}
            </span>
          </div>
          <p class="text-sm text-cyan-200/80 mb-2">CREATED: {{ formatDate(room.createdAt) }}</p>
          <p class="text-sm text-cyan-200/80 mb-4">FILES: {{ room.fileCount }}</p>
          
          <div class="bg-gray-800/50 p-3 rounded border border-cyan-500/20">
            <p class="text-xs text-cyan-400 mb-1">ROOM ACCESS</p>
            <div class="flex items-center">
              <input 
                :value="`${baseUrl}/room/${room.roomId}`"
                readonly
                class="flex-1 bg-gray-900 text-cyan-200 text-xs p-2 rounded-l border border-cyan-500/30 truncate"
              >
              <button 
                @click.stop="copyRoomLink(room.roomId)"
                class="bg-cyan-900/50 hover:bg-cyan-800/70 text-cyan-300 px-3 py-2 rounded-r border border-cyan-500/30 text-xs"
              >
                COPY
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <div v-if="showCreateModal" class="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
      <div class="bg-gray-900 border border-cyan-500/30 rounded-lg p-6 w-full max-w-md">
        <h3 class="text-xl font-bold text-cyan-400 mb-4">CREATE NEW TRANSFER ROOM</h3>
        
        <TerminalInput 
          v-model="newRoomName"
          label="ROOM NAME"
          placeholder="SECURE_TRANSFER_01"
          class="mb-6"
        />
        
        <div class="flex justify-end space-x-4">
          <button 
            @click="showCreateModal = false"
            class="px-4 py-2 border border-red-500/30 text-red-400 hover:bg-red-900/20 transition"
          >
            CANCEL
          </button>
          <NeonButton label="CONFIRM" @click="confirmCreateRoom" :disabled="!newRoomName.trim()" />
        </div>
      </div>
    </div>

    <div v-if="toastMessage" class="fixed bottom-4 right-4 bg-gray-800/90 text-cyan-300 px-4 py-2 rounded border border-cyan-500/30 text-sm">
      {{ toastMessage }}
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { useUserStore } from '@/stores/userStore';
import NeonButton from '@/components/NeonButton.vue';
import TerminalInput from '@/components/TerminalInput.vue';

const userStore = useUserStore();
const router = useRouter();
const rooms = ref([]);
const loading = ref(true);
const error = ref(null);
const showCreateModal = ref(false);
const newRoomName = ref('');
const toastMessage = ref(null);

const baseUrl = import.meta.env.VITE_APP_FRONTEND_URL;


userStore.initialize();

const formatDate = (dateString) => {
  return new Date(dateString).toLocaleString();
};

const copyRoomLink = (roomId) => {
  const link = `${import.meta.env.VITE_APP_FRONTEND_URL}/room/${roomId}`;
  navigator.clipboard.writeText(link);
  toastMessage.value = 'Room link copied to clipboard!';
  setTimeout(() => {
    toastMessage.value = null;
  }, 3000);
};

const fetchRooms = async () => {
  try {
    loading.value = true;
    error.value = null;

    const userResponse = await fetch(`${import.meta.env.VITE_APP_API_URL}/api/users/me`, {
      headers: {
        'Authorization': `Bearer ${userStore.token}`
      }
    });

    if (!userResponse.ok) {
      const errorData = await userResponse.json();
      throw new Error(errorData.error || 'Failed to fetch user info');
    }
    const user = await userResponse.json();

    const roomsResponse = await fetch(`${import.meta.env.VITE_APP_API_URL}/api/users/${user.id}/rooms`, {
      headers: {
        'Authorization': `Bearer ${userStore.token}`
      }
    });

    if (!roomsResponse.ok) {
      const errorData = await roomsResponse.json();
      throw new Error(errorData.error || 'Failed to fetch rooms');
    }
    rooms.value = await roomsResponse.json();
  } catch (err) {
    console.error('Fetch rooms error:', err);
    error.value = err.message || 'Unable to load rooms. Please try again later.';
  } finally {
    loading.value = false;
  }
};

const createNewRoom = () => {
  showCreateModal.value = true;
};

const confirmCreateRoom = async () => {
  if (!newRoomName.value.trim()) {
    error.value = 'Room name is required';
    return;
  }

 try {
    const response = await fetch(`${import.meta.env.VITE_APP_API_URL}/api/rooms`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${userStore.token}`
      },
      body: JSON.stringify({
        name: newRoomName.value
      })
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || 'Failed to create room');
    }

    const newRoom = await response.json();
    rooms.value.push(newRoom);
    showCreateModal.value = false;
    newRoomName.value = '';
    toastMessage.value = `Room "${newRoom.name}" created!`;
    setTimeout(() => {
      toastMessage.value = null;
    }, 3000);

    router.push(`/room/${newRoom.roomId}`);
  } catch (err) {
    console.error('Create room error:', err);
    error.value = err.message || 'Failed to create room. Please try again.';
  }
};

const joinRoom = (roomId) => {
  router.push(`/room/${roomId}`);
};

const confirmDestroyAccount = async () => {
  if (confirm('Are you sure you want to destroy your account? This action cannot be undone.')) {
    try {
      // Note: Backend endpoint for account deletion is not implemented
      userStore.logout();
      router.push('/username');
      toastMessage.value = 'Account destroyed successfully.';
      setTimeout(() => {
        toastMessage.value = null;
      }, 3000);
    } catch (err) {
      console.error('Destroy account error:', err);
      error.value = 'Failed to destroy account. Please try again.';
    }
  }
};

onMounted(() => {
  if (!userStore.isAuthenticated) {
    router.push('/username');
    return;
  }
  fetchRooms();
});
</script>

<style scoped>
/* Animation for toast notification */
@keyframes slideIn {
  from { transform: translateX(100%); }
  to { transform: translateX(0); }
}

div#toast {
  animation: slideIn 0.3s ease-in-out;
}
</style>