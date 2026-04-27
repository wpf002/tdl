// Headless render probe — uses system Chrome to load the dev URL, walks
// every nav view, and reports console errors / page errors / final body
// text length per view.
//
// Requires the dev server to be running. Run:
//   ./run                                    # in another terminal
//   npm install --no-save puppeteer-core     # one-time
//   node tools/smoke_ui.mjs                  # or: npm run test:ui
import puppeteer from 'puppeteer-core'

const URL = process.argv[2] || 'http://localhost:5173/'
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'

const browser = await puppeteer.launch({ executablePath: CHROME, headless: 'new' })
const page = await browser.newPage()

const errors = []
page.on('pageerror', e => errors.push(`pageerror: ${e.message}`))
page.on('console', m => { if (m.type() === 'error' && !m.text().includes('Download the React DevTools')) errors.push(`[console.error] ${m.text()}`) })
page.on('response', async r => { if (r.status() === 404) errors.push(`[404] ${r.url()}`) })

await page.goto(URL, { waitUntil: 'networkidle0', timeout: 15000 })

const VIEWS = ['dashboard', 'rules', 'matrix', 'chains', 'recommend']
const results = []

for (const v of VIEWS) {
  await page.evaluate((label) => {
    const items = Array.from(document.querySelectorAll('.nav-item'))
    const target = items.find(el => el.textContent.toLowerCase().includes(label.toLowerCase().slice(0, 5)))
    if (target) target.click()
  }, v === 'recommend' ? 'recom' : v === 'matrix' ? 'matri' : v === 'chains' ? 'chain' : v === 'rules' ? 'detection' : 'dashb')
  await new Promise(r => setTimeout(r, 250))
  const text = await page.evaluate(() => {
    const main = document.querySelector('.main')
    return main ? main.innerText.length : 0
  })
  results.push({ view: v, mainTextLen: text })
}

console.log('--- ERRORS ---')
errors.forEach(m => console.log(m))
console.log('--- VIEW RENDER ---')
results.forEach(r => console.log(`  ${r.view.padEnd(12)} main.innerText length: ${r.mainTextLen}`))

const apiSourceLive = await page.evaluate(() => document.body.innerText.includes('● live API'))
console.log('--- DATA SOURCE INDICATOR ---')
console.log(`  shows "● live API": ${apiSourceLive}`)

await browser.close()

if (errors.length) process.exit(1)
