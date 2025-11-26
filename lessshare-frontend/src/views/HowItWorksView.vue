<template>
  <div class="container mx-auto px-4 py-12">
    <div class="max-w-4xl mx-auto">
      <h1 class="text-4xl font-bold mb-8 neon-text">HOW LESSSHARE WORKS</h1>
      
      <div class="grid grid-cols-1 md:grid-cols-3 gap-8 mb-12">
        <div class="border-l-2 border-cyan-500 pl-6 py-2">
          <h2 class="text-xl font-bold text-white mb-3">1. CREATE IDENTITY</h2>
          <p class="text-cyan-200/80">Establish your unique username to track your transfer sessions</p>
        </div>
        <div class="border-l-2 border-purple-500 pl-6 py-2">
          <h2 class="text-xl font-bold text-white mb-3">2. INITIATE TRANSFER</h2>
          <p class="text-cyan-200/80">Create a new transfer room or join an existing one</p>
        </div>
        <div class="border-l-2 border-cyan-500 pl-6 py-2">
          <h2 class="text-xl font-bold text-white mb-3">3. CONNECT PEERS</h2>
          <p class="text-cyan-200/80">Share the room ID with recipients to establish direct connections</p>
        </div>
      </div>

      <div class="bg-gray-800/50 border border-cyan-500/30 p-8 rounded-lg mb-12">
        <h2 class="text-2xl font-bold text-cyan-400 mb-6">TECHNOLOGY STACK</h2>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div class="text-center p-4 bg-gray-900/50 rounded">
            <div class="text-3xl mb-2">🌐</div>
            <p class="text-sm font-mono">WebRTC</p>
          </div>
          <div class="text-center p-4 bg-gray-900/50 rounded">
            <div class="text-3xl mb-2">🔒</div>
            <p class="text-sm font-mono">E2E Encryption</p>
          </div>
          <div class="text-center p-4 bg-gray-900/50 rounded">
            <div class="text-3xl mb-2">⚡</div>
            <p class="text-sm font-mono">P2P Network</p>
          </div>
          <div class="text-center p-4 bg-gray-900/50 rounded">
            <div class="text-3xl mb-2">💾</div>
            <p class="text-sm font-mono">Chunk Transfer</p>
          </div>
        </div>
      </div>

      <div class="flex justify-center mt-12">
         <NeonButton label="RETURN TO MAINFRAME" @click="$router.push('/')" />
      </div>
    </div>
  </div>
</template>

<script setup>
import NeonButton from '@/components/NeonButton.vue'
</script>