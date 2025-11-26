<template>
  <nav class="border-b border-cyan-500/20 py-4 px-6 flex justify-between items-center backdrop-blur-sm">
    <router-link to="/" class="text-2xl font-bold neon-text">
      LESSSHARE
    </router-link>
    
    <div class="flex space-x-6">
      <router-link 
        to="/how-it-works" 
        class="hover:text-cyan-300 transition-all duration-300 hover:neon-text"
      >
        HOW IT WORKS
      </router-link>
      <a 
        href="https://github.com/yourusername/lessshare" 
        target="_blank"
        class="hover:text-purple-300 transition-all duration-300 hover:neon-text"
      >
        GITHUB
      </a>
    </div>
  </nav>
</template>

<script setup>
</script>