import { writeFileSync } from 'node:fs'
import type { Page } from '@playwright/test'
import gifenc from 'gifenc'
import { PNG } from 'pngjs'

// gifenc ships as CommonJS, so its functions come off the default export
const { GIFEncoder, applyPalette, quantize } = gifenc

/**
 * Records a page as a GIF by taking screenshots as fast as the browser allows while a demo runs.
 * Each frame lasts until the next one was taken, so the GIF plays at the speed the demo ran.
 */
export async function recordGif(page: Page, path: string, demo: () => Promise<void>) {
  const shots: { png: Buffer; at: number }[] = []
  let recording = true
  const recorder = (async () => {
    while (recording) shots.push({ png: await page.screenshot(), at: Date.now() })
  })()
  try {
    await demo()
  } finally {
    recording = false
    await recorder
  }
  const frames = shots.map(({ png, at }, i) => ({
    image: PNG.sync.read(png),
    delay: (shots[i + 1]?.at ?? at + 3000) - at,
  }))
  writeFileSync(path, encode(frames))
}

/**
 * One palette for the whole GIF (a dashboard has few colours), and each frame stores only the pixels
 * that changed; the rest are transparent so the frame before shows through. Keeps the GIF small.
 */
function encode(frames: { image: PNG; delay: number }[]) {
  const { width, height } = frames[0].image
  const pixels = width * height * 4
  const sample = frames.filter((_, i) => i % Math.ceil(frames.length / 12) === 0)
  const sampled = new Uint8Array(sample.length * pixels)
  sample.forEach(({ image }, i) => sampled.set(image.data, i * pixels))
  const colours = quantize(sampled, 255)
  // An extra entry no pixel is mapped to, for "unchanged"
  const transparent = colours.length
  const palette = [...colours, [255, 0, 255]]

  const out: { index: Uint8Array; delay: number }[] = []
  let onScreen: Uint8Array | null = null
  for (const { image, delay } of frames) {
    const index = applyPalette(new Uint8Array(image.data), colours)
    if (onScreen && index.every((colour, i) => colour === onScreen![i])) {
      // Nothing changed: show the frame before for longer
      out[out.length - 1].delay += delay
      continue
    }
    const changes = onScreen ? index.map((colour, i) => (colour === onScreen![i] ? transparent : colour)) : index
    out.push({ index: changes, delay })
    onScreen = index
  }

  const gif = GIFEncoder()
  out.forEach(({ index, delay }, i) =>
    gif.writeFrame(index, width, height, {
      palette: i === 0 ? palette : undefined,
      delay,
      transparent: i > 0,
      transparentIndex: transparent,
      dispose: 1,
    }),
  )
  gif.finish()
  return gif.bytes()
}
