<template>
  <div class="card">
    <div class="title">{{ title }}</div>
    <div class="value">{{ value }}</div>
    <div v-if="subtitle" class="subtitle">{{ subtitle }}</div>
  </div>
</template>

<script setup lang="ts">
defineProps<{
  title: string;
  value: string | number;
  subtitle?: string;
}>();
</script>

<style scoped>
.card {
  border-radius: 0.75rem;
  border: 1px solid #333;
  padding: 0.8rem 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
}

.title {
  font-size: 0.8rem;
  opacity: 0.75;
}

.value {
  font-size: 1.3rem;
  font-weight: 600;
}

.subtitle {
  font-size: 0.75rem;
  opacity: 0.65;
}
</style>
