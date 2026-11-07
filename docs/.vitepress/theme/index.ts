import DefaultTheme from 'vitepress/theme'
import type { Theme } from 'vitepress'
import BenchmarkResults from './BenchmarkResults.vue'
import './custom.css'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('BenchmarkResults', BenchmarkResults)
  },
} satisfies Theme
