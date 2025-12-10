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
                  <th>sudo_user</th>
                  <th>target_user</th>
                  <th>Comando</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="(e, idx) in events"
                  :key="idx"
                  @click="openDetail(e)"
                  style="cursor: pointer;"
                >
                  <td>{{ formatTs(e.ts || e.timestamp || e.time || "") }}</td>
                  <td>{{ e.hostname || e.host || "-" }}</td>
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
import { onMounted, ref, computed } from "vue";
import { api } from "../../../services/api";
import StatCard from "../../../components/shared/StatCard.vue";
import LoadingSpinner from "../../../components/shared/LoadingSpinner.vue";
import EventDetailDrawer from "../../../components/shared/EventDetailDrawer.vue";

const loading = ref(true);
const error = ref<string | null>(null);
const windowMinutes = ref<number | null>(null);

const events = ref<any[]>([]);

// filtros
const sudoUser = ref<string>("root");
const targetUser = ref<string>("");

// detalle
const showDetail = ref(false);
const detailEvent = ref<any | null>(null);
const detailTitle = ref("Detalle de ejecución sudo");
const detailSubtitle = ref("Evento enviado por /api/v1/sudo_timeline");

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
      minutes: WINDOW_MINUTES,
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
  } catch (e: any) {
    error.value = e?.message ?? String(e);
    events.value = [];
  } finally {
    loading.value = false;
    if (windowMinutes.value === null) {
      windowMinutes.value = WINDOW_MINUTES;
    }
  }
}

function onApplyFilters() {
  void loadData();
}

function openDetail(e: any) {
  detailEvent.value = e;
  showDetail.value = true;
}

onMounted(() => {
  void loadData();
});
</script>

<style scoped>
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
