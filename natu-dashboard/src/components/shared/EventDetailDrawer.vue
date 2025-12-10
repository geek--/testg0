<template>
  <transition name="detail-fade">
    <div
      v-if="modelValue && event"
      class="detail-overlay"
      @click.self="close"
    >
      <div class="detail-panel">
        <header class="detail-panel__header">
          <div>
            <div class="detail-panel__title">{{ title }}</div>
            <div
              v-if="subtitle"
              class="detail-panel__subtitle"
            >
              {{ subtitle }}
            </div>
          </div>
          <button
            type="button"
            class="detail-panel__close"
            @click="close"
          >
            ✕
          </button>
        </header>

        <section class="detail-panel__body">
          <div class="detail-panel__column">
            <h3 class="detail-panel__section-title">Campos</h3>
            <table class="detail-table">
              <tbody>
                <tr
                  v-for="([k, v], idx) in entries"
                  :key="idx"
                >
                  <td class="detail-table__key">{{ k }}</td>
                  <td class="detail-table__value">
                    <span v-if="isPrimitive(v)">{{ String(v) }}</span>
                    <code v-else>{{ shortJson(v) }}</code>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <div class="detail-panel__column">
            <h3 class="detail-panel__section-title">
              Payload crudo (JSON)
            </h3>
            <pre class="detail-panel__json">{{ prettyJson }}</pre>
          </div>
        </section>
      </div>
    </div>
  </transition>
</template>

<script setup lang="ts">
import { computed } from "vue";

const props = defineProps<{
  modelValue: boolean;
  title: string;
  subtitle?: string;
  event: Record<string, any> | null;
}>();

const emit = defineEmits<{
  (e: "update:modelValue", value: boolean): void;
}>();

function close() {
  emit("update:modelValue", false);
}

const entries = computed(() => {
  if (!props.event) return [];
  return Object.entries(props.event);
});

const prettyJson = computed(() =>
  props.event ? JSON.stringify(props.event, null, 2) : "",
);

function isPrimitive(v: unknown): boolean {
  return (
    v === null ||
    ["string", "number", "boolean", "bigint"].includes(typeof v)
  );
}

function shortJson(v: unknown): string {
  try {
    const s = JSON.stringify(v);
    return s.length > 80 ? s.slice(0, 77) + "..." : s;
  } catch {
    return String(v);
  }
}
</script>

<style scoped>
.detail-fade-enter-active,
.detail-fade-leave-active {
  transition: opacity 0.15s ease;
}
.detail-fade-enter-from,
.detail-fade-leave-to {
  opacity: 0;
}

.detail-overlay {
  position: fixed;
  inset: 0;
  background: radial-gradient(
      circle at top left,
      rgba(15, 23, 42, 0.9),
      rgba(15, 23, 42, 0.96)
    );
  backdrop-filter: blur(6px);
  z-index: 80;
  display: flex;
  justify-content: center;
  align-items: center; /* 👈 centrado vertical */
  padding: 1.5rem;
}

.detail-panel {
  width: 100%;
  max-width: 1100px;
  max-height: 80vh;
  background: radial-gradient(
      circle at top left,
      rgba(59, 130, 246, 0.12),
      transparent
    ),
    rgba(15, 23, 42, 0.98);
  border-radius: 1rem;
  border: 1px solid rgba(148, 163, 184, 0.4);
  box-shadow: 0 18px 45px rgba(0, 0, 0, 0.65);
  display: flex;
  flex-direction: column;
}

.detail-panel__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.9rem 1.2rem;
  border-bottom: 1px solid rgba(148, 163, 184, 0.3);
}

.detail-panel__title {
  font-size: 0.98rem;
  font-weight: 600;
  color: #e5e7eb;
}

.detail-panel__subtitle {
  font-size: 0.75rem;
  color: #9ca3af;
  margin-top: 0.15rem;
}

.detail-panel__close {
  border: none;
  background: rgba(15, 23, 42, 0.9);
  border-radius: 9999px;
  width: 1.5rem;
  height: 1.5rem;
  color: #9ca3af;
  cursor: pointer;
  font-size: 0.8rem;
}

.detail-panel__close:hover {
  background: rgba(30, 64, 175, 0.7);
  color: #f9fafb;
}

.detail-panel__body {
  padding: 0.9rem 1.2rem 1.1rem;
  display: grid;
  grid-template-columns: minmax(0, 1.1fr) minmax(0, 1.2fr);
  gap: 1rem;
  overflow: auto;
}

.detail-panel__column {
  min-width: 0;
}

.detail-panel__section-title {
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: #9ca3af;
  margin-bottom: 0.35rem;
}

.detail-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.78rem;
}

.detail-table__key {
  width: 32%;
  padding: 0.25rem 0.35rem;
  color: #9ca3af;
  vertical-align: top;
}

.detail-table__value {
  padding: 0.25rem 0.35rem;
  color: #e5e7eb;
  word-break: break-word;
}

.detail-panel__json {
  background: rgba(15, 23, 42, 0.95);
  border-radius: 0.5rem;
  border: 1px solid rgba(51, 65, 85, 0.9);
  padding: 0.5rem 0.7rem;
  font-size: 0.72rem;
  color: #e5e7eb;
  max-height: 60vh;
  overflow: auto;
}
</style>
