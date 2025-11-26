<template>
  <div class="container mx-auto px-4 py-12 flex flex-col items-center justify-center min-h-[80vh]">
    <div class="w-full max-w-md bg-gray-800/50 border border-cyan-500/30 p-8 rounded-lg backdrop-blur-sm">
      <h2 class="text-2xl font-bold text-cyan-400 mb-6 text-center">IDENTIFY YOURSELF</h2>
      
      <TerminalInput 
        v-model="username"
        label="ENTER USERNAME"
        placeholder="USER_1234"
        class="mb-6"
        @keyup.enter="saveUsername"
      />
      
      <NeonButton 
        @click="saveUsername"
        :disabled="!usernameValid || isLoading"
        class="w-full"
      >
        <span v-if="isLoading" class="flex items-center justify-center">
          <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          PROCESSING...
        </span>
        <span v-else>CONFIRM IDENTITY</span>
      </NeonButton>
      
      <div v-if="error" class="mt-4 p-3 bg-red-900/50 border border-red-500/30 text-red-300 rounded text-sm">
        <div class="flex items-start">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
          </svg>
          <div>
            <p class="font-bold">IDENTITY VERIFICATION FAILED</p>
            <p class="mt-1">{{ error }}</p>
          </div>
        </div>
      </div>
    </div>
    
    <div class="mt-12 text-xs text-cyan-400/50">
      <p>USER IDENTIFICATION REQUIRED FOR SESSION TRACKING</p>
      <p class="mt-1">MIN 3 CHARACTERS • MAX 20 CHARACTERS</p>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useUserStore } from '@/stores/userStore'
import NeonButton from '@/components/NeonButton.vue'
import TerminalInput from '@/components/TerminalInput.vue'

const route = useRoute(); // Added for accessing query parameters
const userStore = useUserStore()
const router = useRouter()
const username = ref('')
const error = ref('')
const isLoading = ref(false)

const usernameValid = computed(() => {
  return username.value.length >= 3 && username.value.length <= 20
})

const saveUsername = async () => {
  if (!usernameValid.value) {
    error.value = 'Username must be between 3-20 characters'
    return
  }

  isLoading.value = true
  error.value = ''

  console.log(`${import.meta.env.VITE_APP_API_URL}/api/users`)

  try {
    const response = await fetch(`${import.meta.env.VITE_APP_API_URL}/api/users`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username: username.value })
    })
    
    const data = await response.json()
    
    if (!response.ok) {
      throw new Error(data.error || 'Failed to verify identity')
    }
    
    userStore.login(data.user, data.token)
    // Redirect to the original room if roomId is provided, otherwise to /rooms
    const redirectRoomId = route.query.roomId;
    router.push(redirectRoomId ? `/room/${redirectRoomId}` : '/rooms')
  } catch (err) {
    console.error('Registration error:', err)
    error.value = err.message || 'Network communication failure'
    
    // Auto-clear error after 5 seconds
    setTimeout(() => {
      error.value = ''
    }, 5000)
  } finally {
    isLoading.value = false
  }
}
</script>

<style scoped>
/* Animation for error message */
.error-message {
  animation: fadeIn 0.3s ease-in-out;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(-10px); }
  to { opacity: 1; transform: translateY(0); }
}
</style>