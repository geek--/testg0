<template>
  <div class="app-shell">
    <aside class="app-shell__sidebar">
      <div class="sidebar__brand">
        <div class="sidebar__badge">N</div>
        <div class="sidebar__title">
          <span class="sidebar__title-main">natu-core</span>
          <span class="sidebar__title-sub">Accesos &amp; Privilegios</span>
        </div>
      </div>

      <div>
        <div class="sidebar__section-label">Módulos</div>
        <nav class="sidebar__nav">
          <RouterLink
            to="/ssh"
            class="sidebar__link"
            :class="{ 'sidebar__link--active': isSSHModuleActive }"
          >
            <span class="sidebar__link-dot"></span>
            <span class="sidebar__link-label">SSH / sudo</span>
            <span class="sidebar__link-pill">En vivo</span>
          </RouterLink>
        </nav>
      </div>

      <div class="sidebar__footer">
        <div class="sidebar__section-label">Estado</div>
        <div class="sidebar__status-pill">
          <span>●</span>
          <span>isov3 · agente conectado</span>
        </div>
      </div>
    </aside>

    <div class="app-shell__main">
      <header class="app-shell__topbar">
        <div class="topbar__titles">
          <div class="topbar__title-main">
            Módulo Accesos &amp; Privilegios
            <span class="topbar__pill">SSH + sudo</span>
          </div>
          <div class="topbar__subtitle">
            Vista de control y monitoreo para accesos interactivos al servidor isov3.
          </div>
        </div>
        <div class="topbar__right">
          <div class="topbar__badge-criticality">
            <span>Criticality:</span>
            <strong>Informational</strong>
          </div>
        </div>
      </header>

      <main class="app-shell__content">
        <slot />
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { RouterLink, useRoute } from "vue-router";
import { computed } from "vue";

const route = useRoute();

// Consideramos activo todo lo que empiece por /ssh (overview, alertas, sudo, etc.)
const isSSHModuleActive = computed(() => route.path.startsWith("/ssh"));
</script>
