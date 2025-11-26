<template>
  <div class="bg-black bg-opacity-60 rounded-lg border border-cyan-400 mb-4">
    <button
      class="w-full p-4 text-left text-cyan-300 font-bold text-xl neon-text flex justify-between items-center"
      @click="toggle"
    >
      <span>{{ title }}</span>
      <span class="text-2xl">{{ isOpen ? '-' : '+' }}</span>
    </button>
    <div v-if="isOpen" class="p-4">
      <slot />
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue';

defineProps({
  title: { type: String, required: true }
});

const isOpen = ref(false);

const toggle = () => {
  isOpen.value = !isOpen.value;
};
</script>

<style scoped>
.neon-text {
  text-shadow: 0 0 5px #00f6ff, 0 0 10px #00f6ff, 0 0 20px #00f6ff;
  transition: all 0.3s ease;
}

.neon-text:hover {
  text-shadow: 0 0 10px #00f6ff, 0 0 20px #00f6ff, 0 0 30px #00f6ff;
}
</style>