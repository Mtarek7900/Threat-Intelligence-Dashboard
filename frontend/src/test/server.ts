import { setupServer } from 'msw/node'

// Tests register their own handlers with server.use(); anything unhandled fails the test
export const server = setupServer()
