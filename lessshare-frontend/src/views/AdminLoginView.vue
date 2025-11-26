<template>
  <div class="min-h-screen flex items-center justify-center p-4">
    <div class="relative bg-gray-800/50 p-8 rounded-lg border border-cyan-400/50 max-w-md w-full backdrop-blur-sm">
      <!-- Grid overlay effect -->
      <div class="absolute inset-0 opacity-20 pointer-events-none">
        <div class="h-full w-full bg-grid-pattern"></div>
      </div>
      
      <div class="relative z-10">
        <div class="text-center mb-8">
          <div class="inline-block border-b border-cyan-400/30 pb-2 mb-4">
            <h2 class="text-3xl font-bold text-cyan-300 neon-text tracking-wider">SYSTEM ACCESS</h2>
          </div>
          <p class="text-cyan-400/80 text-sm font-mono">ADMIN CREDENTIALS REQUIRED</p>
        </div>
        
        <div class="space-y-6">
          <TerminalInput
            v-model="username"
            label="ADMIN ID"
            placeholder="ENTER AUTHORIZATION CODE"
            class="mb-4"
          />
          
          <TerminalInput
            v-model="password"
            label="ACCESS KEY"
            placeholder="ENTER ENCRYPTION KEY"
            type="password"
          />
          
          <div class="pt-2">
            <NeonButton
              @click="login"
              :disabled="loading"
              class="w-full"
            >
              <span v-if="loading" class="flex items-center justify-center">
                <svg class="animate-spin -ml-1 mr-3 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                AUTHENTICATING...
              </span>
              <span v-else>INITIATE ACCESS</span>
            </NeonButton>
          </div>
          
          <div v-if="error" class="mt-2 p-3 bg-red-900/50 border border-red-500/30 text-red-300 rounded text-sm">
            <div class="flex items-start">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
              </svg>
              <div>
                <p class="font-bold">ACCESS DENIED</p>
                <p class="mt-1">{{ error }}</p>
              </div>
            </div>
          </div>
        </div>
        
        <div class="mt-8 pt-4 border-t border-cyan-400/20 text-center">
          <p class="text-gray-400 text-sm">
            UNAUTHORIZED PERSONNEL? <router-link to="/username" class="text-cyan-400 hover:text-cyan-300 font-mono">RETURN TO USER PORTAL</router-link>
          </p>
        </div>
      </div>
    </div>
    
    <!-- Status terminal effect -->
    <div class="fixed bottom-0 left-0 right-0 bg-black bg-opacity-80 border-t border-cyan-400/30 p-2 text-cyan-400/50 text-xs font-mono overflow-hidden">
      <div class="animate-marquee whitespace-nowrap">
        SYSTEM STATUS: ONLINE • SECURITY PROTOCOLS: ACTIVE • LAST ACCESS: {{
          new Date().toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
          })
        }} • ENCRYPTION: AES-256 • SYSTEM STATUS: ONLINE
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { useUserStore } from '../stores/userStore';
import TerminalInput from '../components/TerminalInput.vue';
import NeonButton from '../components/NeonButton.vue';

const userStore = useUserStore();
const router = useRouter();
const username = ref('');
const password = ref('');
const loading = ref(false);
const error = ref(null);

const login = async () => {
  if (!username.value || !password.value) {
    error.value = 'AUTHENTICATION FIELDS REQUIRED';
    return;
  }

  loading.value = true;
  error.value = null;

  try {
    console.log(`${import.meta.env.VITE_APP_API_URL}/api/admin/login`)
    const response = await fetch(`${import.meta.env.VITE_APP_API_URL}/api/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username.value, password: password.value })
    });

    if (!response.ok) {
      const data = await response.json();
      throw new Error(data.error || 'AUTHENTICATION FAILURE');
    }

    const data = await response.json();
    userStore.login(data.user, data.token);
    router.push('/dashboard');
  } catch (err) {
    error.value = err.message;
    console.error('Admin login failed:', err);
  } finally {
    loading.value = false;
  }
};
</script>

<style scoped>
.bg-grid-pattern {
  background-image: 
    linear-gradient(to right, rgba(0, 246, 255, 0.05) 1px, transparent 1px),
    linear-gradient(to bottom, rgba(0, 246, 255, 0.05) 1px, transparent 1px);
  background-size: 20px 20px;
}

.neon-text {
  text-shadow: 0 0 5px #00f6ff, 0 0 10px #00f6ff;
  animation: flicker 1.5s infinite alternate;
}

@keyframes flicker {
  0%, 18%, 22%, 25%, 53%, 57%, 100% {
    text-shadow:
      0 0 4px #00f6ff,
      0 0 11px #00f6ff,
      0 0 19px #00f6ff;
  }
  20%, 24%, 55% {
    text-shadow: none;
  }
}

@keyframes marquee {
  0% { transform: translateX(0); }
  100% { transform: translateX(-50%); }
}

.animate-marquee {
  display: inline-block;
  animation: marquee 20s linear infinite;
}
</style>