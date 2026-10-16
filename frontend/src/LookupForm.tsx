import { useState, type FormEvent } from 'react'

/**
 * @param onLookUp makes a Lookup of the input as the Analyst typed it
 * @param lookingUp whether a Lookup is under way
 */
export function LookupForm({ onLookUp, lookingUp }: { onLookUp: (input: string) => void; lookingUp: boolean }) {
  const [input, setInput] = useState('')

  function submit(event: FormEvent) {
    event.preventDefault()
    onLookUp(input)
  }

  return (
    <form onSubmit={submit} className="flex gap-2">
      <label htmlFor="indicator" className="sr-only">
        Indicator
      </label>
      <input
        id="indicator"
        value={input}
        onChange={(event) => setInput(event.target.value)}
        placeholder="Paste an IP address, domain or file hash"
        autoComplete="off"
        spellCheck={false}
        className="flex-1 rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-slate-900 focus:border-slate-500 focus:outline-none"
      />
      <button
        type="submit"
        disabled={lookingUp}
        className="rounded-lg bg-slate-900 px-4 py-2 font-medium text-white hover:bg-slate-700 disabled:opacity-50"
      >
        Look up
      </button>
    </form>
  )
}
