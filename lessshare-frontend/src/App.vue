<template>
  <div class="min-h-screen bg-gray-900 text-cyan-100 font-mono overflow-hidden w-full">
    <div class="glow-overlay"></div>
    <div class="scanlines"></div>
    <NavBar />
    <router-view class="relative z-10" />
  </div>
</template>

<script setup>
import NavBar from './components/NavBar.vue'
</script>

<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');

body {
  font-family: 'Share Tech Mono', monospace;
  position: relative;
}

.glow-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: 
    radial-gradient(circle at 20% 30%, rgba(0, 255, 255, 0.1) 0%, transparent 30%),
    radial-gradient(circle at 80% 70%, rgba(255, 0, 255, 0.1) 0%, transparent 30%);
  pointer-events: none;
  z-index: 1;
}

.scanlines {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: 
    linear-gradient(
      to bottom,
      rgba(0, 255, 255, 0.03) 0%,
      rgba(0, 255, 255, 0.03) 50%,
      transparent 50%,
      transparent 100%
    );
  background-size: 100% 4px;
  pointer-events: none;
  z-index: 1;
}

.neon-text {
  text-shadow: 0 0 5px #0ff, 0 0 10px #0ff, 0 0 15px #0ff;
}
</style>