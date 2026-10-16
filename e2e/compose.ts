import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const e2eDir = fileURLToPath(new URL('.', import.meta.url))

/** Runs `docker compose` against the smoke test's stack (compose.yaml), showing its output. */
export function compose(...args: string[]) {
  execFileSync('docker', ['compose', ...args], { cwd: e2eDir, stdio: 'inherit' })
}
