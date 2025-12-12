<template>
  <div class="page">
    <header class="page-header">
      <h1 class="page-header__title">Accesos & Privilegios · Reactividad</h1>
      <p class="page-header__subtitle">
        Bans activos de Fail2ban/ipset para SSH y sudo del servidor isov3, consumidos en vivo desde
        natu-core.
      </p>
      <div class="tabs">
        <a href="/ssh" class="tab">SSH (resumen)</a>
        <a href="/ssh/activity" class="tab">SSH (actividad)</a>
        <a href="/ssh/alerts" class="tab">Alertas SSH</a>
        <span class="tab tab-active">Reactividad</span>
        <a href="/ssh/sudo" class="tab">Sudo (resumen)</a>
        <a href="/ssh/sudo/activity" class="tab">Sudo (actividad)</a>
        <a href="/ssh/sudo-alerts" class="tab">Alertas sudo</a>
        <a href="/ssh/criticality" class="tab">Criticidad</a>
      </div>
    </header>

    <section class="page" style="gap: 0.75rem; display: flex; flex-direction: column;">
      <div class="activity-toolbar">
        <div class="activity-toolbar__group">
          <label class="activity-toolbar__label">Ventana (min)</label>
          <input
            v-model.number="windowMinutes"
            class="activity-toolbar__input"
            type="number"
            min="5"
            max="10080"
          />

          <div class="quick-window">
            <span class="window-selector__label">Rápidos:</span>
            <button
              v-for="opt in quickWindows"
              :key="opt"
              type="button"
              class="window-selector__btn"
              :class="{ 'window-selector__btn--active': windowMinutes === opt }"
              @click="setWindow(opt)"
            >
              <span v-if="opt >= 1440">{{ opt / 1440 }} día(s)</span>
              <span v-else>{{ opt / 60 }} h</span>
            </button>
          </div>

          <button class="btn-secondary" type="button" @click="refreshData(true)">
            Refrescar ahora
          </button>
          <span class="activity-toolbar__hint">Actualizado: {{ lastUpdatedLabel }}</span>
        </div>

        <div class="activity-toolbar__group">
          <label class="activity-toolbar__label">Filtro rápido</label>
          <input
            v-model="filter"
            class="activity-toolbar__input"
            type="text"
            placeholder="Filtra por IP, host o jail"
          />
        </div>
      </div>

      <div class="stats-grid">
        <StatCard
          title="Bans activos"
          :value="bans.length"
          subtitle="IPs presentes en ssh_bans_state"
        />
        <StatCard
          title="Hosts reportando"
          :value="uniqueHosts"
          subtitle="Agentes con sync OK en la ventana"
        />
        <StatCard
          title="Ventana analizada"
          :value="windowLabel"
          subtitle="Parámetro minutes en /api/v1/ssh_bans"
        />
      </div>

      <div class="table-card">
        <div class="table-card__title">Bans Fail2ban/ipset</div>

        <div v-if="loading" class="section--loading">
          <LoadingSpinner /> Cargando bans activos...
        </div>
        <div v-else-if="error" class="section--error">{{ error }}</div>
        <table v-else class="table">
          <thead>
            <tr>
              <th>IP</th>
              <th>Host</th>
              <th>Jail</th>
              <th>Ban desde</th>
              <th>Último sync</th>
              <th>Fuente</th>
              <th>Razón</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(ban, idx) in filteredBans" :key="ban.ip + idx">
              <td>{{ ban.ip }}</td>
              <td>{{ ban.hostname }}</td>
              <td>{{ ban.jail }}</td>
              <td>{{ formatTs(ban.banned_at || ban.synced_at) }}</td>
              <td>{{ formatTs(ban.synced_at) }}</td>
              <td>{{ ban.source || 'fail2ban' }}</td>
              <td>{{ ban.reason || 'active ban' }}</td>
            </tr>
            <tr v-if="filteredBans.length === 0">
              <td colspan="7" style="font-size: 0.82rem; color: #9ca3af;">
                No hay bans activos en la ventana seleccionada o no coinciden con el filtro.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import LoadingSpinner from "../../../components/shared/LoadingSpinner.vue";
import StatCard from "../../../components/shared/StatCard.vue";
import { api } from "../../../services/api";
import type { SSHBanItem, SSHBanResponse } from "../types";

const windowMinutes = ref<number>(1440);
const quickWindows = [60, 720, 1440, 10080];
const filter = ref<string>("");
const bans = ref<SSHBanItem[]>([]);
const loading = ref<boolean>(false);
const error = ref<string>("");
const generatedAt = ref<string>("");

const windowLabel = computed(() => {
  if (windowMinutes.value >= 1440) {
    return `${windowMinutes.value / 1440} día(s)`;
  }
  return `${windowMinutes.value} min`;
});

const uniqueHosts = computed(() => {
  const set = new Set(bans.value.map((b) => b.hostname));
  return set.size;
});

const lastUpdatedLabel = computed(() => {
  if (!generatedAt.value) return "-";
  const date = new Date(generatedAt.value);
  return date.toISOString();
});

const filteredBans = computed(() => {
  if (!filter.value) return bans.value;
  const term = filter.value.toLowerCase();
  return bans.value.filter(
    (b) =>
      b.ip.toLowerCase().includes(term) ||
      b.hostname.toLowerCase().includes(term) ||
      b.jail.toLowerCase().includes(term),
  );
});

async function refreshData(manual = false) {
  if (loading.value && !manual) return;
  loading.value = true;
  error.value = "";

  try {
    const data = await api.get<SSHBanResponse>("/ssh_bans", {
      minutes: windowMinutes.value,
    });
    bans.value = data.bans || [];
    generatedAt.value = data.generated_at;
  } catch (err: any) {
    error.value = err?.message || "Error cargando bans";
  } finally {
    loading.value = false;
  }
}

function setWindow(minutes: number) {
  windowMinutes.value = minutes;
}

function formatTs(ts?: string) {
  if (!ts) return "-";
  const d = new Date(ts);
  return d.toISOString();
}

watch(windowMinutes, () => refreshData());

onMounted(() => {
  refreshData(true);
});
</script>

<style scoped>
.page {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.page-header__subtitle {
  max-width: 960px;
}

.activity-toolbar {
  display: flex;
  gap: 1rem;
  flex-wrap: wrap;
  align-items: flex-end;
}

.activity-toolbar__group {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.activity-toolbar__label {
  font-size: 0.9rem;
  color: #e5e7eb;
}

.activity-toolbar__input {
  background: #111827;
  border: 1px solid #1f2937;
  padding: 0.35rem 0.55rem;
  color: #e5e7eb;
  border-radius: 0.35rem;
}

.activity-toolbar__hint {
  color: #9ca3af;
  font-size: 0.85rem;
}

.quick-window {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  flex-wrap: wrap;
}

.window-selector__label {
  color: #9ca3af;
  font-size: 0.85rem;
}

.window-selector__btn {
  background: #0b1220;
  color: #d1d5db;
  border: 1px solid #1f2937;
  padding: 0.3rem 0.65rem;
  border-radius: 0.4rem;
  font-size: 0.85rem;
}

.window-selector__btn--active {
  background: #1f2937;
  border-color: #334155;
  color: #f3f4f6;
}

.table-card__title {
  font-weight: 700;
  color: #e5e7eb;
  margin-bottom: 0.35rem;
}

.section--loading,
.section--error {
  padding: 1rem;
}

.stats-grid {
  display: grid;
  gap: 0.75rem;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
}
</style>
