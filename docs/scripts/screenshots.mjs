// Takes the screenshots of the documentation from the real server.
//
// Starts redirect-proxy (`gleam run -- serve`) on free ports with a throwaway
// data directory holding docs/screenshots/redirects.json, makes a few changes
// so that the audit log, users and API clients have something to show, then
// captures the admin pages into docs/public/screenshots/ (git-ignored: the
// docs workflow regenerates them on every build, so they follow the UI).
//
// Needs Gleam and Erlang (see .tool-versions) and the Playwright browser:
//   npx playwright install chromium
import { spawn } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright'

const docs = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const root = resolve(docs, '..')
const out = join(docs, 'public', 'screenshots')
const fixture = join(docs, 'screenshots', 'redirects.json')
const username = 'admin'
const password = 'documentation-password'

function freePort() {
  return new Promise((ok, fail) => {
    const srv = createServer()
    srv.on('error', fail)
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => ok(port))
    })
  })
}

async function waitFor(url, server, timeoutMs = 120_000) {
  const until = Date.now() + timeoutMs
  while (Date.now() < until) {
    if (server.exitCode !== null) throw new Error(`the server exited (${server.exitCode})`)
    try {
      if ((await fetch(url)).ok) return
    } catch {
      // not listening yet
    }
    await new Promise((r) => setTimeout(r, 250))
  }
  throw new Error(`${url} did not answer in ${timeoutMs / 1000} s`)
}

// Hit counts and last hits, so that the list has its "Hits" column filled.
// Deterministic, so that the pictures only change when the UI does.
function hits(ids) {
  const now = Math.floor(Date.now() / 1000)
  const entries = ids.map((id, i) => {
    const count = i === 11 ? 0 : Math.round(48_000 / (i + 1.6) ** 1.5)
    return [id, { count, last: count === 0 ? 0 : now - (i * 7_919) % 86_400 }]
  })
  return { version: 1, hits: Object.fromEntries(entries) }
}

const data = mkdtempSync(join(tmpdir(), 'redirect-proxy-docs-'))
copyFileSync(fixture, join(data, 'redirects.json'))
const ids = (await import(fixture, { with: { type: 'json' } })).default.rules.map((r) => r.id)
writeFileSync(join(data, 'hits.json'), JSON.stringify(hits(ids)))

const [trafficPort, adminPort] = [await freePort(), await freePort()]
const admin = `http://127.0.0.1:${adminPort}`
const server = spawn('gleam', ['run', '--', 'serve'], {
  cwd: root,
  detached: true,
  stdio: ['ignore', 'inherit', 'inherit'],
  env: {
    ...process.env,
    RP_CONFIG: join(root, 'config.example.toml'),
    RP_STORAGE_DATA_DIR: data,
    RP_SERVER_LISTEN: '127.0.0.1',
    RP_SERVER_PORT: String(trafficPort),
    RP_ADMIN_LISTEN: '127.0.0.1',
    RP_ADMIN_PORT: String(adminPort),
    RP_ADMIN_PUBLIC_URL: admin,
    // only shown in the usage examples of the API clients page
    RP_API_PUBLIC_URL: 'https://redirects.example.com',
    RP_BOOTSTRAP_ADMIN_USERNAME: username,
    RP_BOOTSTRAP_ADMIN_PASSWORD: password,
    RP_ACCESS_LOG_ENABLED: 'false',
    RP_LOG_LEVEL: 'warning',
  },
})

function stop() {
  try {
    process.kill(-server.pid, 'SIGTERM')
  } catch {
    // already gone
  }
  rmSync(data, { recursive: true, force: true })
}
process.on('SIGINT', () => {
  stop()
  process.exit(130)
})

let browser
try {
  await waitFor(`${admin}/healthz`, server)
  rmSync(out, { recursive: true, force: true })
  mkdirSync(out, { recursive: true })

  browser = await chromium.launch()
  const context = await browser.newContext({
    viewport: { width: 1280, height: 800 },
    deviceScaleFactor: 2,
    colorScheme: 'light',
    locale: 'en-US',
    timezoneId: 'UTC',
  })
  const page = await context.newPage()
  const shot = async (name, opts = {}) => {
    await page.waitForLoadState('networkidle')
    await page.screenshot({ path: join(out, `${name}.png`), ...opts })
    console.log(`screenshots: ${name}.png`)
  }

  // Signed out.
  await page.goto(`${admin}/login`)
  await shot('login', { clip: { x: 0, y: 0, width: 1280, height: 360 } })

  await page.fill('input[name=username]', username)
  await page.fill('input[name=password]', password)
  await Promise.all([page.waitForURL(/\/rules/), page.click('form:has(input[name=password]) [type=submit]')])

  // A few changes, for the audit log, users and API clients pages.
  await page.goto(`${admin}/rules/docs-faq/edit`)
  await page.fill('input[name=target]', '/v2/help/frequently-asked-questions')
  await page.fill('input[name=note]', 'The FAQ page was renamed')
  await Promise.all([page.waitForURL(/\/rules(\?|$)/), page.click('form[action="/rules/docs-faq"] [type=submit]')])

  await page.goto(`${admin}/rules/go-survey/edit`)
  await page.uncheck('input[name=enabled]')
  await Promise.all([page.waitForURL(/\/rules(\?|$)/), page.click('form[action="/rules/go-survey"] [type=submit]')])

  await page.goto(`${admin}/users`)
  await page.fill('form[action="/users"] input[name=username]', 'camille')
  await page.fill('form[action="/users"] input[name=password]', 'another-long-password')
  await page.selectOption('form[action="/users"] select[name=role]', 'editor')
  await Promise.all([page.waitForLoadState('load'), page.click('form[action="/users"] [type=submit]')])

  await page.goto(`${admin}/api-clients`)
  await page.fill('form[action="/api-clients"] input[name=name]', 'ci-deploy')
  await page.check('form[action="/api-clients"] input[name=scope][value="redirects:write"]')
  await Promise.all([page.waitForLoadState('load'), page.click('form[action="/api-clients"] [type=submit]')])
  await shot('api-client-created')

  // The pages.
  await page.goto(`${admin}/rules?sort=-hits`)
  await shot('rules')

  await page.goto(`${admin}/rules/blog-legacy/edit`)
  await shot('rule-form', { fullPage: true })

  await page.goto(`${admin}/test?url=${encodeURIComponent('https://example.com/blog/2024/05/hello-world/')}`)
  await shot('tester', { clip: { x: 0, y: 0, width: 1280, height: 400 } })

  await page.goto(`${admin}/import`)
  await page.fill(
    'textarea[name=content]',
    [
      'id,host,source,target,status,tags',
      'about,example.com,/about-us,/company,301,site-2025',
      ',example.com,/team,/company/team,301,site-2025',
      ',example.com,/partners,/company/partners,301,site-2025',
    ].join('\n'),
  )
  await page.check('input[name=mode][value=merge]')
  await Promise.all([page.waitForLoadState('load'), page.click('form[action="/import"] [name=step][value=preview]')])
  await shot('import-preview', { clip: { x: 0, y: 0, width: 1280, height: 340 } })

  await page.goto(`${admin}/users`)
  await shot('users')

  await page.goto(`${admin}/api-clients`)
  await shot('api-clients')

  await page.goto(`${admin}/audit`)
  // open the change of a rule: before and after, field by field
  await page.locator('summary', { hasText: 'docs-faq' }).first().click()
  await shot('audit')
} finally {
  await browser?.close()
  stop()
}
