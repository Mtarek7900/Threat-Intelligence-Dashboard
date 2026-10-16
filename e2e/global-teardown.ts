import { compose } from './compose'

export default function globalTeardown() {
  // --volumes so every run starts from an empty database
  compose('down', '--volumes')
}
