<template>
  <Teleport to="body">
    <transition name="fade">
      <div v-if="modelValue" class="edm-overlay" @click.self="close">
        <div class="edm-panel">
          <header class="edm-header">
            <div>
              <h2 class="edm-title">{{ title }}</h2>
              <p v-if="subtitle" class="edm-subtitle">{{ subtitle }}</p>
            </div>
            <button class="edm-close" type="button" @click="close">✕</button>
          </header>

          <section class="edm-section">
            <h3 class="edm-section-title">Campos principales</h3>
            <dl class="edm-grid">
              <template v-for="(value, key) in flatFields" :key="key">
                <dt>{{ key }}</dt>
                <dd>{{ value }}</dd>
              </template>
              <p v-if="!Object.keys(flatFields).length" class="edm-empty">
                No hay campos legibles para este evento.
              </p>
            </dl>
          </section>

          <section class="edm-section">
            <details open class="edm-details">
              <summary>Raw event JSON</summary>
              <pre class="edm-pre">{{ prettyJson }}</pre>
            </details>
          </section>
        </div>
      </div>
    </transition>
  </Teleport>
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

const prettyJson = computed(() =>
  props.event ? JSON.stringify(props.event, null, 2) : "{}",
);

const flatFields = computed<Record<string, string>>(() => {
  if (!props.event) return {};
  const out: Record<string, string> = {};
  const keysToHighlight = [
    "ts",
    "timestamp",
    "time",
    "hostname",
    "host",
    "remote_ip",
    "ip",
    "source_ip",
    "username",
    "user",
    "sudo_user",
    "target_user",
    "tty",
    "command",
    "cmd",
    "binary",
    "rule",
    "severity",
    "message",
    "reason",
    "failed_before",
    "failed",
    "success",
    "exit_code",
    "result",
    "status",
    "outcome",
  ];

  for (const key of keysToHighlight) {
    const v = (props.event as any)[key];
    if (
      v === null ||
      v === undefined ||
      (typeof v === "string" && v.trim() === "")
    ) {
      continue;
    }
    out[key] = String(v);
  }

  return out;
});

function close() {
  emit("update:modelValue", false);
}
</script>

<style scoped>
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.18s ease-out;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

.edm-overlay {
  position: fixed;
  inset: 0;
  background: rgba(15, 23, 42, 0.75);
  display: flex;
  justify-content: flex-end;
  z-index: 80;
}

.edm-panel {
  width: min(460px, 100%);
  height: 100%;
  background: radial-gradient(
      circle at top left,
      rgba(56, 189, 248, 0.16),
      transparent
    ),
    #020617;
  border-left: 1px solid rgba(148, 163, 184, 0.35);
  padding: 1rem 1.1rem 1.2rem;
  box-shadow: -12px 0 30px rgba(15, 23, 42, 0.9);
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.edm-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 0.75rem;
  border-bottom: 1px solid rgba(148, 163, 184, 0.25);
  padding-bottom: 0.55rem;
}

.edm-title {
  font-size: 1rem;
  font-weight: 600;
  color: #e5e7eb;
}

.edm-subtitle {
  font-size: 0.75rem;
  color: #9ca3af;
  margin-top: 0.1rem;
}

.edm-close {
  border: none;
  background: transparent;
  color: #9ca3af;
  cursor: pointer;
  font-size: 0.9rem;
  padding: 0.15rem 0.25rem;
  border-radius: 9999px;
}
.edm-close:hover {
  background: rgba(148, 163, 184, 0.16);
  color: #f9fafb;
}

.edm-section {
  padding-top: 0.4rem;
}

.edm-section-title {
  font-size: 0.78rem;
  letter-spacing: 0.03em;
  text-transform: uppercase;
  color: #9ca3af;
  margin-bottom: 0.35rem;
}

.edm-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 2fr);
  gap: 0.2rem 0.75rem;
  font-size: 0.78rem;
  color: #e5e7eb;
}

.edm-grid dt {
  color: #9ca3af;
}
.edm-grid dd {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas,
    "Liberation Mono", "Courier New", monospace;
}

.edm-empty {
  grid-column: 1 / -1;
  font-size: 0.75rem;
  color: #6b7280;
}

.edm-details summary {
  cursor: pointer;
  font-size: 0.8rem;
  color: #9ca3af;
  margin-bottom: 0.35rem;
}

.edm-pre {
  background: rgba(15, 23, 42, 0.95);
  border-radius: 0.5rem;
  border: 1px solid rgba(31, 41, 55, 0.9);
  padding: 0.5rem 0.7rem;
  font-size: 0.72rem;
  max-height: 340px;
  overflow: auto;
  color: #e5e7eb;
}
</style>
