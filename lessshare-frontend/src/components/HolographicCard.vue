<template>
  <div class="relative h-full border border-cyan-500/20 hover:border-cyan-500/50 transition-all duration-500 overflow-hidden group">
    <div class="h-full p-6 bg-gray-900/50 backdrop-blur-sm">
      <div class="text-4xl mb-4 text-cyan-400">{{ icon }}</div>
      <h3 class="text-xl font-bold text-white mb-2">{{ title }}</h3>
      <p class="text-cyan-200/80">{{ description }}</p>
    </div>
    <div class="absolute inset-0 bg-gradient-to-br from-cyan-500/10 to-purple-500/10 opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"></div>
    <div class="absolute inset-0 border-t border-l border-cyan-500/30 w-12 h-12 opacity-0 group-hover:opacity-100 transition-opacity duration-500 delay-75 pointer-events-none"></div>
    <div class="absolute bottom-0 right-0 border-b border-r border-cyan-500/30 w-12 h-12 opacity-0 group-hover:opacity-100 transition-opacity duration-500 delay-100 pointer-events-none"></div>
  </div>
</template>

<script setup>
defineProps({
  title: String,
  icon: String,
  description: String
})
</script>