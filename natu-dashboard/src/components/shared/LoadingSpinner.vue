<template>
  <div class="spinner-wrapper">
    <div class="spinner"></div>
  </div>
</template>

<script setup lang="ts"></script>

<style scoped>
.spinner-wrapper {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
}

.spinner {
  width: 1rem;
  height: 1rem;
  border-radius: 999px;
  border: 2px solid #444;
  border-top-color: #2b6cb0;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
</style>
