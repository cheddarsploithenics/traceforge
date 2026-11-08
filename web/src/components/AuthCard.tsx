import { type FormEvent, useState } from "react";

import type { SessionInfo } from "../api/client";

export type AuthState =
  | { kind: "checking" }
  | { kind: "signed-out"; message?: string }
  | { kind: "signed-in"; session: SessionInfo };

interface AuthCardProps {
  state: AuthState;
  onSignIn: (code: string) => void;
  onSignOut: () => void;
}

function formatTime(iso: string | null): string {
  return iso ? new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "";
}

export function AuthCard({ state, onSignIn, onSignOut }: AuthCardProps) {
  const [code, setCode] = useState("");

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const trimmed = code.trim();
    if (trimmed) {
      setCode("");
      onSignIn(trimmed);
    }
  };

  if (state.kind === "checking") {
    return (
      <section className="card card--pending" aria-labelledby="auth-title">
        <h2 id="auth-title">Session</h2>
        <p role="status">Checking session…</p>
      </section>
    );
  }

  if (state.kind === "signed-in") {
    return (
      <section className="card card--ok" aria-labelledby="auth-title">
        <header className="card__header">
          <h2 id="auth-title">Session</h2>
          <button type="button" onClick={onSignOut}>
            Sign out
          </button>
        </header>
        <p>
          Signed in
          {state.session.expires_at && ` · expires at ${formatTime(state.session.expires_at)}`}
        </p>
      </section>
    );
  }

  return (
    <section className="card card--error" aria-labelledby="auth-title">
      <h2 id="auth-title">Sign in</h2>
      {state.message && <p role="alert">{state.message}</p>}
      <p>
        Run <code>traceforge dashboard-link</code> in a terminal and open the printed link. The
        server also prints one when it starts. Links work once and expire after a few minutes.
      </p>
      <form className="signin" onSubmit={submit}>
        <label htmlFor="login-code">Or paste a sign-in code</label>
        <input
          id="login-code"
          type="password"
          autoComplete="off"
          spellCheck={false}
          value={code}
          onChange={(e) => setCode(e.target.value)}
        />
        <button type="submit">Sign in</button>
      </form>
    </section>
  );
}
