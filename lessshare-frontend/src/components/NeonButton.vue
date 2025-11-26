<template>
  <button
    :disabled="disabled"
    @click="$emit('click')"
    class="relative px-6 py-3 font-mono font-bold tracking-wider text-cyan-100 transition-all duration-300 overflow-hidden group"
    :class="{
      'opacity-50 cursor-not-allowed': disabled,
      'cursor-pointer': !disabled
    }"
  >
    <span class="relative z-10 flex items-center justify-center gap-2">
      <slot>{{ label }}</slot>
    </span>
    
    <!-- Main button background -->
    <span class="absolute inset-0 bg-gray-800/70 border border-cyan-500/30 group-hover:border-cyan-400/70 transition-all duration-300"></span>
    
    <!-- Neon glow effect -->
    <span class="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
      <span class="absolute inset-0 bg-cyan-500/10"></span>
      <span class="absolute inset-0 shadow-[0_0_15px_2px_rgba(34,211,238,0.5)]"></span>
    </span>
    
    <!-- Animated border elements -->
    <span class="absolute top-0 left-0 w-3 h-3 border-t border-l border-cyan-400 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></span>
    <span class="absolute top-0 right-0 w-3 h-3 border-t border-r border-cyan-400 opacity-0 group-hover:opacity-100 transition-opacity duration-500 delay-100"></span>
    <span class="absolute bottom-0 left-0 w-3 h-3 border-b border-l border-cyan-400 opacity-0 group-hover:opacity-100 transition-opacity duration-500 delay-200"></span>
    <span class="absolute bottom-0 right-0 w-3 h-3 border-b border-r border-cyan-400 opacity-0 group-hover:opacity-100 transition-opacity duration-500 delay-300"></span>
    
    <!-- Animated scanning line -->
    <span class="absolute top-0 left-0 w-full h-0.5 bg-cyan-400/30 opacity-0 group-hover:opacity-100 transition-opacity duration-700">
      <span class="absolute top-0 left-0 h-full w-8 bg-cyan-400 animate-[scan_2s_linear_infinite]"></span>
    </span>
  </button>
</template>

<script setup>
defineProps({
  label: {
    type: String,
    default: 'BUTTON'
  },
  disabled: {
    type: Boolean,
    default: false
  }
})

defineEmits(['click'])
</script>

<style>
@keyframes scan {
  0% {
    transform: translateX(-100%);
  }
  100% {
    transform: translateX(calc(100vw + 100%));
  }
}
</style>