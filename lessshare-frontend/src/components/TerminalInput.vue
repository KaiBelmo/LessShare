<template>
  <div class="relative">
    <label class="block text-xs text-cyan-400 mb-1">{{ label }}</label>
    <div class="relative">
      <input
        v-model="inputValue"
        :placeholder="placeholder"
        :type="type"
        class="w-full bg-gray-900 border border-cyan-500/30 focus:border-cyan-500/70 px-4 py-3 text-cyan-100 placeholder-cyan-500/50 outline-none transition-all duration-300"
      />
      <div class="absolute right-0 top-0 h-full w-10 bg-gradient-to-l from-gray-900 to-transparent flex items-center justify-center">
        <div class="h-3 w-3 bg-cyan-400 animate-pulse"></div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  label: String,
  placeholder: String,
  modelValue: String,
  type: {
    type: String,
    default: 'text'
  }
})

const emit = defineEmits(['update:modelValue'])

const inputValue = computed({
  get() {
    return props.modelValue
  },
  set(value) {
    emit('update:modelValue', value)
  }
})
</script>