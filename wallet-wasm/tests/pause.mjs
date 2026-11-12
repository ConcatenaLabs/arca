// The library's pause, against the built package (`wasm-pack build --target web --out-name
// leaf_wallet`), under Node:
//
//   node wallet-wasm/tests/pause.mjs wallet-wasm/pkg
//
// - with the host's wait given (`setPause`, here `Atomics.wait`), a 2 s pause costs the thread
//   under 50 ms of processor time;
// - with none, or one that returns at once or throws, the pause is still whole (never shorter
//   than asked, within the 2 ms by which the clock the library watches and the one measuring it
//   can differ), watching the clock.
import { readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const pkg = resolve(process.argv[2] || 'wallet-wasm/pkg')
const mod = await import(pathToFileURL(join(pkg, 'leaf_wallet.js')).href)
await mod.default({ module_or_path: readFileSync(join(pkg, 'leaf_wallet_bg.wasm')) })
if (typeof mod.setPause !== 'function' || typeof mod.pause !== 'function') {
  console.error('FAIL: the package exports no setPause and pause'); process.exit(1)
}

function measure (ms) {
  const c0 = process.cpuUsage(), t0 = performance.now()
  mod.pause(ms)
  const c = process.cpuUsage(c0)
  return { wall: performance.now() - t0, cpu: (c.user + c.system) / 1000 }
}

let failed = 0
function check (what, ok, m) {
  console.log(`${ok ? 'ok' : 'FAIL'}: ${what}: ${m.wall.toFixed(0)} ms waited, ${m.cpu.toFixed(1)} ms of processor`)
  if (!ok) failed++
}

const waits = []
mod.setPause((ms) => { waits.push(ms); Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms) })
let m = measure(2000)
check('a 2 s pause through the host\'s wait', m.wall >= 1998 && m.cpu < 50 && waits.length === 1 && waits[0] === 2000, m)

mod.setPause((ms) => { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms / 2) })
m = measure(1000)
check('a host\'s wait that ends at half time: the pause is whole', m.wall >= 998, m)

mod.setPause(() => { throw new Error('no wait here') })
m = measure(500)
check('a host\'s wait that throws: the pause is whole', m.wall >= 498, m)

mod.setPause(null)
m = measure(500)
check('no host\'s wait: the pause is whole, on the clock', m.wall >= 498 && m.cpu > 250, m)

process.exit(failed ? 1 : 0)
