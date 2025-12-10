<template>
  <div class="page">
    <header class="page-header">
      <h1 class="page-header__title">Sudo · Alertas</h1>
      <p class="page-header__subtitle">
        Alertas generadas por el uso de sudo en el servidor isov3:
        comandos sensibles, shells elevadas y otros comportamientos anómalos.
      </p>
      <div class="tabs">
        <a href="/ssh" class="tab">SSH (resumen)</a>
        <a href="/ssh/activity" class="tab">SSH (actividad)</a>
        <a href="/ssh/alerts" class="tab">Alertas SSH</a>
        <a href="/ssh/sudo" class="tab">Sudo (actividad)</a>
        <span class="tab tab-active">Alertas sudo</span>
      </div>
    </header>

    <!-- Estado: cargando -->
    <section v-if="loading" class="section--loading">
      <LoadingSpinner /> Cargando alertas de sudo...
    </section>

    <!-- Estado: error -->
    <section v-else-if="error" class="section--error">
      Error al cargar alertas de sudo: {{ error }}
    </section>

    <!-- Datos OK -->
    <section v-else class="page">
      <div class="stats-grid">
        <StatCard
          title="Ventana analizada"
          :value="(windowMinutes ?? WINDOW_MINUTES) + ' min'"
          subtitle="Parámetro minutes en /api/v1/sudo_alerts"
        />

        <StatCard
          title="Alertas sudo"
          :value="alerts.length"
          subtitle="Alertas generadas por actividad sudo en la ventana"
        />

        <StatCard
          title="Usuarios involucrados"
          :value="distinctUsers"
          subtitle="Usuarios únicos presentes en alertas sudo"
        />

        <StatCard
          title="Última alerta"
          :value="lastAlertTsDisplay"
          subtitle="Marca de tiempo de la alerta más reciente"
        />
      </div>

      <section
        v-if="alerts.length === 0"
        class="section--loading"
        style="margin-top: 0.9rem;"
      >
        No se han registrado alertas sudo en la ventana seleccionada.
      </section>

      <section
        v-else
        style="margin-top: 0.9rem;"
      >
        <div class="table-card">
          <div class="table-card__title">Alertas sudo recientes</div>
          <table class="table">
            <thead>
              <tr>
                <th>Fecha/Hora</th>
                <th>Host</th>
                <th>Usuario</th>
                <th>Comando</th>
                <th>Severidad</th>
                <th>Regla</th>
                <th>Mensaje</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(a, idx) in alerts" :key="idx">
                <td>{{ formatTs(a.ts || a.timestamp || a.time || "") }}</td>
                <td>{{ a.hostname || a.host || "-" }}</td>
                <td>{{ a.username || a.user || "-" }}</td>
                <td>{{ a.command || a.cmd || a.binary || "-" }}</td>
                <td>{{ a.severity || a.level || "-" }}</td>
                <td>{{ a.rule || a.type || "-" }}</td>
                <td>{{ a.message || a.msg || a.description || "-" }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </section>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref, computed } from "vue";
import { api } from "../../../services/api";
import StatCard from "../../../components/shared/StatCard.vue";
import LoadingSpinner from "../../../components/shared/LoadingSpinner.vue";

const loading = ref(true);
const error = ref<string | null>(null);
const windowMinutes = ref<number | null>(null);
const alerts = ref<any[]>([]);

// por ahora fijo; luego configurable
const WINDOW_MINUTES = 240;

const distinctUsers = computed(() => {
  const set = new Set<string>();
  for (const a of alerts.value) {
    const u = (a.username || a.user) as string | undefined;
    if (u) set.add(u);
  }
  return set.size;
});

const lastAlertTsDisplay = computed(() => {
  if (!alerts.value.length) return "—";
  const last = alerts.value.reduce((latest, current) => {
    const tCurrent = new Date(
      (current.ts || current.timestamp || current.time || "") as string,
    ).getTime();
    const tLatest = new Date(
      (latest.ts || latest.timestamp || latest.time || "") as string,
    ).getTime();
    return tCurrent > tLatest ? current : latest;
  }, alerts.value[0]);
  return formatTs(
    (last.ts || last.timestamp || last.time || "") as string,
  );
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
    const res = await api.get<any>("/sudo_alerts", {
      minutes: WINDOW_MINUTES,
    });

    if (typeof res?.window_minutes === "number") {
      windowMinutes.value = res.window_minutes;
    } else {
      windowMinutes.value = WINDOW_MINUTES;
    }

    const rawAlerts =
      res?.alerts ??
      res?.items ??
      res?.events ??
      res?.data ??
      (Array.isArray(res) ? res : []);

    alerts.value = Array.isArray(rawAlerts) ? rawAlerts : [];
  } catch (e: any) {
    error.value = e?.message ?? String(e);
  } finally {
    loading.value = false;
    if (windowMinutes.value === null) windowMinutes.value = WINDOW_MINUTES;
  }
}

onMounted(() => {
  void loadData();
});
</script>
