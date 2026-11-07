<script setup lang="ts">
// Renders docs/data/benchmark.json, written by scripts/bench-compare.py
// (the Benchmark workflow refreshes it every week).
import { computed, ref } from 'vue'
import results from '../../data/benchmark.json'

type Scenario = { rps: number; p50_ms: number; p99_ms: number; errors: number }
type Product = {
  key: string
  name: string
  image: string
  version: string
  digest: string
  status: 'ok' | 'failed'
  error?: string
  notes: string[]
  startup_ms?: number
  memory_mib?: number | null
  scenarios?: Record<string, Scenario>
}

const labels: Record<string, string> = {
  exact: 'Exact hit',
  prefix: 'Prefix hit',
  regex: 'Last regex',
  miss: 'Miss (404)',
}
const scenarios = Object.keys(results.scenarios)
const selected = ref(scenarios[0])
const products = results.products as Product[]

const rows = computed(() => {
  const ok = products.filter((p) => p.status === 'ok' && p.scenarios)
  const max = Math.max(...ok.map((p) => p.scenarios![selected.value].rps), 1)
  return products.map((p) => {
    const s = p.status === 'ok' ? p.scenarios![selected.value] : undefined
    return { p, s, width: s ? (s.rps / max) * 100 : 0 }
  })
})

const number = new Intl.NumberFormat('en-US')
const ms = (v: number) => (v < 1 ? v.toFixed(2) : v.toFixed(1)) + ' ms'
</script>

<template>
  <div class="bench">
    <p class="bench-meta">
      Measured on {{ results.date }} on a {{ results.runner.host }}
      ({{ results.runner.vcpus }} vCPUs<template v-if="results.runner.cpu">, {{ results.runner.cpu }}</template>),
      {{ results.server_cpus }} of them for the server, with
      {{ number.format(results.rules.exact) }} exact, {{ number.format(results.rules.prefix) }} prefix and
      {{ number.format(results.rules.regex) }} regex rules.
    </p>

    <div class="bench-tabs" role="tablist" aria-label="Scenario">
      <button
        v-for="s in scenarios"
        :key="s"
        role="tab"
        :aria-selected="selected === s"
        :class="{ active: selected === s }"
        @click="selected = s"
      >
        {{ labels[s] ?? s }}
      </button>
    </div>
    <p class="bench-path">
      <code>GET {{ results.scenarios[selected].path }}</code> →
      <code>{{ results.scenarios[selected].status }}</code>, requests per second (higher is better)
    </p>

    <div class="bench-bars">
      <template v-for="{ p, s, width } in rows" :key="p.key">
        <div class="bench-name">{{ p.name }}</div>
        <div class="bench-bar">
          <div v-if="s" class="fill" :class="{ ours: p.key === 'redirect-proxy' }" :style="{ width: width + '%' }"></div>
          <span class="value">{{ s ? number.format(s.rps) : 'failed' }}</span>
        </div>
      </template>
    </div>

    <table>
      <thead>
        <tr>
          <th>Server</th>
          <th>Version</th>
          <th class="num">p50</th>
          <th class="num">p99</th>
          <th class="num">Memory</th>
          <th class="num">Start-up</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="{ p, s } in rows" :key="p.key">
          <td>{{ p.name }}</td>
          <td>
            <code :title="p.digest ? p.image + '@' + p.digest : p.image">{{ p.version }}</code>
          </td>
          <template v-if="s">
            <td class="num">{{ ms(s.p50_ms) }}</td>
            <td class="num">{{ ms(s.p99_ms) }}</td>
            <td class="num">{{ p.memory_mib != null ? Math.round(p.memory_mib) + ' MiB' : '?' }}</td>
            <td class="num">{{ p.startup_ms != null ? number.format(p.startup_ms) + ' ms' : '?' }}</td>
          </template>
          <td v-else colspan="4">failed: {{ p.error }}</td>
        </tr>
      </tbody>
    </table>

    <details class="bench-notes">
      <summary>How each server is configured</summary>
      <ul>
        <li v-for="p in products" :key="p.key">
          <strong>{{ p.name }}</strong> (<code>{{ p.image }}</code>):
          <span v-if="p.notes.length === 0">its own rules file.</span>
          <span v-for="(n, i) in p.notes" :key="i">{{ n }}{{ i < p.notes.length - 1 ? '; ' : '.' }}</span>
        </li>
      </ul>
    </details>
  </div>
</template>

<style scoped>
.bench-meta,
.bench-path {
  color: var(--vp-c-text-2);
  font-size: 14px;
}
.bench-tabs {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin: 16px 0 8px;
}
.bench-tabs button {
  border: 1px solid var(--vp-c-divider);
  border-radius: 20px;
  padding: 4px 14px;
  font-size: 14px;
  color: var(--vp-c-text-2);
  transition: border-color 0.2s, color 0.2s;
}
.bench-tabs button:hover {
  border-color: var(--vp-c-brand-1);
}
.bench-tabs button.active {
  border-color: var(--vp-c-brand-1);
  color: var(--vp-c-brand-1);
  background: var(--vp-c-brand-soft);
}
.bench-bars {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 8px 12px;
  align-items: center;
  margin: 16px 0 24px;
}
.bench-name {
  font-size: 14px;
}
.bench-bar {
  position: relative;
  display: flex;
  align-items: center;
  min-height: 24px;
  background: var(--vp-c-bg-soft);
  border-radius: 4px;
}
.bench-bar .fill {
  position: absolute;
  inset: 0 auto 0 0;
  border-radius: 4px;
  background: var(--vp-c-gray-1);
  opacity: 0.55;
}
.bench-bar .fill.ours {
  background: var(--vp-c-brand-1);
  opacity: 0.85;
}
.bench-bar .value {
  position: relative;
  padding-left: 8px;
  font-size: 13px;
  font-variant-numeric: tabular-nums;
}
.num {
  text-align: right;
  font-variant-numeric: tabular-nums;
}
.bench-notes {
  font-size: 14px;
  color: var(--vp-c-text-2);
}
.bench-notes summary {
  cursor: pointer;
}
</style>
