<template>
  <div class="page">
    <header class="page-header">
      <h1 class="page-header__title">Sudo · Actividad reciente</h1>
      <p class="page-header__subtitle">
        Ejecuciones de sudo, usuarios que lo utilizan y comandos elevando privilegios
        en el servidor isov3.
      </p>
      <div class="tabs">
        <a href="/ssh" class="tab">SSH (resumen)</a>
        <a href="/ssh/activity" class="tab">SSH (actividad)</a>
        <a href="/ssh/alerts" class="tab">Alertas SSH</a>
        <span class="tab tab-active">Sudo (actividad)</span>
        <a href="/ssh/sudo-alerts" class="tab">Alertas sudo</a>
        <a href="/ssh/criticality" class="tab">Criticidad</a>
      </div>
    </header>

    <!-- Filtros -->
    <section class="page" style="margin-bottom: 0.75rem;">
      <form class="filters-bar" @submit.prevent="onApplyFilters">
        <div class="filters-bar__group">
          <label class="filters-bar__label">
            Usuario sudo (<code>sudo_user</code>)
          </label>
          <input
            v-model="sudoUser"
            class="filters-bar__input"
            type="text"
            placeholder="Ej: root"
          />
        </div>

        <div class="filters-bar__group">
          <label class="filters-bar__label">
            <span>target_user</span>
            <span class="filters-bar__label-badge">opcional</span>
          </label>
          <input
            v-model="targetUser"
            class="filters-bar__input"
            type="text"
            placeholder="Ej: root"
          />
        </div>

        <div class="filters-bar__actions">
          <button type="submit" class="btn-primary">
            Aplicar filtros
          </button>
        </div>
      </form>
      <p class="filters-bar__hint">
        El endpoint <code>/api/v1/sudo_timeline</code> requiere al menos
        <code>sudo_user</code> o <code>target_user</code>. Si no indicas nada,
        se usará <strong>sudo_user = "root"</strong>.
      </p>
    </section>

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
        <button class="btn-secondary" type="button" @click="refreshData()">
          Refrescar ahora
        </button>
        <span class="activity-toolbar__hint">Actualizado: {{ lastUpdatedLabel }}</span>
      </div>

      <div class="activity-toolbar__group">
        <label class="activity-toolbar__label">Auto-refresco</label>
        <select v-model.number="selectedInterval" class="activity-toolbar__input">
          <option v-for="opt in intervalOptions" :key="opt" :value="opt">
            Cada {{ opt }}s
          </option>
        </select>
        <label class="activity-toolbar__toggle">
          <input type="checkbox" v-model="autoRefreshEnabled" />
          <span>Activado</span>
        </label>
      </div>
    </div>

    <!-- Estado: cargando -->
    <section v-if="loading" class="section--loading">
      <LoadingSpinner /> Cargando actividad de sudo...
    </section>

    <!-- Estado: error -->
    <section v-else-if="error" class="section--error">
      Error al cargar datos de sudo: {{ error }}
    </section>

    <!-- Datos OK -->
    <section v-else class="page">
      <!-- Cards resumen -->
      <div class="stats-grid">
        <StatCard
          title="Ventana analizada"
          :value="(windowMinutes ?? WINDOW_MINUTES) + ' min'"
          subtitle="Parámetro minutes en /api/v1/sudo_timeline"
        />

        <StatCard
          title="Ejecuciones sudo"
          :value="events.length"
          subtitle="Total de eventos sudo registrados en la ventana"
        />

        <StatCard
          title="Usuarios con sudo"
          :value="usersSummary.length"
          subtitle="Cantidad de usuarios (sudo_user) que usaron sudo en estos eventos"
        />

        <StatCard
          title="Comandos distintos"
          :value="distinctCommands"
          subtitle="Número aproximado de binarios/comandos usados con sudo"
        />
      </div>

      <!-- Mensaje si no hay datos -->
      <section
        v-if="events.length === 0"
        class="section--loading"
        style="margin-top: 0.9rem;"
      >
        No se han registrado ejecuciones sudo en la ventana seleccionada
        para los filtros actuales.
      </section>

      <section
        v-else
        class="page"
        style="margin-top: 0.9rem;"
      >
        <div class="tables-grid">
          <!-- Top usuarios sudo -->
          <div class="table-card">
            <div class="table-card__title">Top usuarios usando sudo</div>
            <table class="table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Usuario</th>
                  <th>Comandos sudo</th>
                  <th>Último uso</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="(u, idx) in usersSummary"
                  :key="u.username + '-' + idx"
                  class="row--clickable"
                  @click="openDetail(u, 'Top usuarios usando sudo', 'Usuario sudo')"
                >
                  <td>{{ idx + 1 }}</td>
                  <td>{{ u.username }}</td>
                  <td>{{ u.count }}</td>
                  <td>{{ formatTs(u.lastTs) }}</td>
                </tr>
              </tbody>
            </table>
          </div>

          <!-- Actividad sudo cruda -->
          <div class="table-card">
            <div class="table-card__title">Actividad sudo (últimos eventos)</div>
            <table class="table">
              <thead>
                <tr>
                  <th>Fecha/Hora</th>
                  <th>Host</th>
                  <th>IP</th>
                  <th>sudo_user</th>
                  <th>target_user</th>
                  <th>Comando</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="(e, idx) in events"
                  :key="idx"
                  class="row--clickable"
                  @click="openDetail(e)"
                >
                  <td>{{ formatTs(e.ts || e.timestamp || e.time || "") }}</td>
                  <td>{{ e.hostname || e.host || "-" }}</td>
                  <td>{{ e.remote_ip || e.ip || e.source_ip || "-" }}</td>
                  <td>{{ e.sudo_user || e.username || e.user || "-" }}</td>
                  <td>{{ e.target_user || "-" }}</td>
                  <td>{{ e.command || e.cmd || e.binary || "-" }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </section>

    <EventDetailDrawer
      v-model="showDetail"
      :title="detailTitle"
      :subtitle="detailSubtitle"
      :event="detailEvent"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { api } from "../../../services/api";
import StatCard from "../../../components/shared/StatCard.vue";
import LoadingSpinner from "../../../components/shared/LoadingSpinner.vue";
import EventDetailDrawer from "../../../components/shared/EventDetailDrawer.vue";

const loading = ref(true);
const error = ref<string | null>(null);
const windowMinutes = ref<number>(240);
const lastUpdated = ref<Date | null>(null);

const events = ref<any[]>([]);

// filtros
const sudoUser = ref<string>("root");
const targetUser = ref<string>("");

// detalle
const showDetail = ref(false);
const detailEvent = ref<any | null>(null);
const detailTitle = ref("Detalle de ejecución sudo");
const detailSubtitle = ref("Evento enviado por /api/v1/sudo_timeline");

const intervalOptions = [5, 10, 30, 60];
const selectedInterval = ref<number>(30);
const autoRefreshEnabled = ref<boolean>(true);
let refreshHandle: number | null = null;

// por ahora fijo; luego configurable
const WINDOW_MINUTES = 240;

const usersSummary = computed(() => {
  const map = new Map<
    string,
    { username: string; count: number; lastTs: string }
  >();

  for (const e of events.value) {
    const username =
      (e.sudo_user || e.username || e.user || "desconocido") as string;
    const ts = (e.ts || e.timestamp || e.time || "") as string;

    const current = map.get(username) ?? {
      username,
      count: 0,
      lastTs: "",
    };

    current.count += 1;

    if (ts) {
      const dCurrent = new Date(ts).getTime();
      const dLast = current.lastTs ? new Date(current.lastTs).getTime() : 0;
      if (dCurrent > dLast) current.lastTs = ts;
    }

    map.set(username, current);
  }

  return Array.from(map.values()).sort((a, b) => b.count - a.count);
});

const distinctCommands = computed(() => {
  const set = new Set<string>();
  for (const e of events.value) {
    const cmd = (e.command || e.cmd || e.binary) as string | undefined;
    if (cmd) set.add(cmd);
  }
  return set.size;
});

const lastUpdatedLabel = computed(() => {
  if (!lastUpdated.value) return "—";
  return lastUpdated.value.toLocaleTimeString();
});

function formatTs(ts: string): string {
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts || "—";
  return d.toLocaleString();
}

async function loadData() {
  loading.value = true;
  error.value = null;

  try {
    const params: Record<string, any> = {
      minutes: windowMinutes.value || WINDOW_MINUTES,
    };

    if (sudoUser.value || targetUser.value) {
      if (sudoUser.value) params.sudo_user = sudoUser.value;
      if (targetUser.value) params.target_user = targetUser.value;
    } else {
      params.sudo_user = "root";
    }

    const res = await api.get<any>("/sudo_timeline", params);

    if (typeof res?.window_minutes === "number") {
      windowMinutes.value = res.window_minutes;
    } else {
      windowMinutes.value = WINDOW_MINUTES;
    }

    const rawEvents =
      res?.events ??
      res?.items ??
      res?.points ??
      res?.data ??
      (Array.isArray(res) ? res : []);

    events.value = Array.isArray(rawEvents) ? rawEvents : [];
    lastUpdated.value = new Date(res?.generated_at ?? Date.now());
  } catch (e: any) {
    error.value = e?.message ?? String(e);
    events.value = [];
  } finally {
    loading.value = false;
    if (!windowMinutes.value) {
      windowMinutes.value = WINDOW_MINUTES;
    }
  }
}

function onApplyFilters() {
  void refreshData();
}

async function refreshData() {
  await loadData();
}

function openDetail(
  e: any,
  subtitle = "Evento enviado por /api/v1/sudo_timeline",
  title = "Detalle de ejecución sudo",
) {
  detailEvent.value = e;
  detailSubtitle.value = subtitle;
  detailTitle.value = title;
  showDetail.value = true;
}

function clearAutoRefresh() {
  if (refreshHandle) {
    window.clearInterval(refreshHandle);
    refreshHandle = null;
  }
}

function setupAutoRefresh() {
  clearAutoRefresh();
  if (!autoRefreshEnabled.value) return;

  refreshHandle = window.setInterval(() => {
    void refreshData();
  }, selectedInterval.value * 1000);
}

watch([selectedInterval, autoRefreshEnabled], () => {
  setupAutoRefresh();
});

watch(windowMinutes, () => {
  void refreshData();
});

onMounted(() => {
  void refreshData();
  setupAutoRefresh();
});

onBeforeUnmount(() => {
  clearAutoRefresh();
});
</script>

<style scoped>
.row--clickable {
  cursor: pointer;
}

.activity-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
  padding: 0.45rem 0.6rem;
  border: 1px solid rgba(148, 163, 184, 0.25);
  border-radius: 0.75rem;
  background: rgba(15, 23, 42, 0.6);
}

.activity-toolbar__group {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.activity-toolbar__label {
  font-size: 0.82rem;
  color: #cbd5e1;
}

.activity-toolbar__input {
  background: rgba(15, 23, 42, 0.9);
  border: 1px solid rgba(148, 163, 184, 0.3);
  border-radius: 0.5rem;
  padding: 0.3rem 0.5rem;
  color: #e2e8f0;
  min-width: 90px;
}

.activity-toolbar__hint {
  font-size: 0.78rem;
  color: #94a3b8;
}

.activity-toolbar__toggle {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  font-size: 0.9rem;
  color: #e2e8f0;
}

.btn-secondary {
  border-radius: 9999px;
  border: 1px solid rgba(148, 163, 184, 0.35);
  background: rgba(15, 23, 42, 0.9);
  padding: 0.3rem 0.75rem;
  font-size: 0.8rem;
  color: #e5e7eb;
  cursor: pointer;
}

.btn-secondary--active {
  background: linear-gradient(90deg, #2563eb, #4f46e5);
  border-color: transparent;
}

.filters-bar {
  display: flex;
  gap: 1rem;
  align-items: flex-end;
  padding: 0.75rem 1rem;
  border-radius: 0.75rem;
  border: 1px solid rgba(148, 163, 184, 0.16);
  background: radial-gradient(
      circle at top left,
      rgba(56, 189, 248, 0.08),
      transparent
    ),
    rgba(15, 23, 42, 0.9);
}

.filters-bar__group {
  display: flex;
  flex-direction: column;
  min-width: 180px;
}

.filters-bar__label {
  font-size: 0.75rem;
  color: #9ca3af;
  margin-bottom: 0.25rem;
  display: flex;
  align-items: center;
  gap: 0.35rem;
}

.filters-bar__label-badge {
  font-size: 0.65rem;
  padding: 0.05rem 0.45rem;
  border-radius: 9999px;
  border: 1px solid rgba(148, 163, 184, 0.4);
  color: #9ca3af;
}

.filters-bar__input {
  background: rgba(15, 23, 42, 0.9);
  border-radius: 0.5rem;
  border: 1px solid rgba(148, 163, 184, 0.5);
  padding: 0.35rem 0.6rem;
  font-size: 0.85rem;
  color: #e5e7eb;
}

.filters-bar__input::placeholder {
  color: #6b7280;
}

.filters-bar__actions {
  margin-left: auto;
}

.btn-primary {
  border-radius: 9999px;
  border: none;
  padding: 0.4rem 0.9rem;
  font-size: 0.8rem;
  background: linear-gradient(90deg, #2563eb, #4f46e5);
  color: #f9fafb;
  cursor: pointer;
  white-space: nowrap;
}

.btn-primary:hover {
  filter: brightness(1.08);
}

.filters-bar__hint {
  margin-top: 0.4rem;
  font-size: 0.68rem;
  color: #9ca3af;
}
</style>
