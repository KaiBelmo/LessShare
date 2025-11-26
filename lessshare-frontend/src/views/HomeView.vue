<template>
  <div
    class="container mx-auto px-4 py-12 flex flex-col items-center justify-center min-h-[80vh]"
  >
    <div class="text-center mb-16">
      <h1 class="text-5xl md:text-6xl font-bold mb-6 neon-text">
        P2PFILESHARING
      </h1>
      <p class="text-lg text-cyan-200 max-w-2xl mx-auto">
        Direct, encrypted file transfers powered by WebRTC. No servers. No
        middlemen.
      </p>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-3 gap-8 mb-16 w-full max-w-6xl">
      <HolographicCard
        title="PRIVATE"
        icon="🔒"
        description="End-to-end encrypted transfers that never touch our servers"
      />
      <HolographicCard
        title="FAST"
        icon="⚡"
        description="Peer-to-peer connections for maximum transfer speeds"
      />
      <HolographicCard
        title="DECENTRALIZED"
        icon="🌐"
        description="No central point of failure. Works even if we go offline"
      />
    </div>

    <NeonButton label="INITIATE TRANSFER" @click="startSharing" />


    <div class="mt-12 text-cyan-300/70 text-sm">
      <p>SYSTEM STATUS: <span class="text-green-400">ONLINE</span></p>
      <p class="mt-1">ACTIVE NODES: 1,427</p>
    </div>
  </div>
</template>

<script setup>
import NeonButton from "@/components/NeonButton.vue";
import HolographicCard from "@/components/HolographicCard.vue";
import { useRouter } from "vue-router";

const router = useRouter();

const startSharing = () => {
  router.push("/username");
};
</script>
