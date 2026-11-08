import { type FormEvent, useState } from "react";

import { BrandMark, Icon } from "../components/Icon";
import { HealthIndicator, type HealthState } from "../layout/Topbar";

interface SignInPageProps {
  health: HealthState;
  checking: boolean;
  message?: string;
  onSignIn: (code: string) => void;
  onRetryHealth: () => void;
}

export function SignInPage({ health, checking, message, onSignIn, onRetryHealth }: SignInPageProps) {
  const [code, setCode] = useState("");

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const trimmed = code.trim();
    if (trimmed) {
      setCode("");
      onSignIn(trimmed);
    }
  };

  return (
    <div className="auth-screen">
      <main className="auth-card">
        <div className="auth-card__brand">
          <BrandMark size={28} />
          <span>TraceForge</span>
        </div>

        {checking ? (
          <p role="status" className="muted">
            Checking session…
          </p>
        ) : (
          <>
            <h1>Sign in</h1>
            {message && (
              <p role="alert" className="callout callout--critical">
                {message}
              </p>
            )}
            <p className="auth-card__lead">
              Run <code>traceforge dashboard-link</code> in a terminal and open the printed link. The
              server also prints one when it starts. Links work once and expire after a few minutes.
            </p>
            <form className="form" onSubmit={submit}>
              <label className="form__label" htmlFor="login-code">
                Or paste a sign-in code
              </label>
              <div className="input-row">
                <input
                  id="login-code"
                  className="input"
                  type="password"
                  autoComplete="off"
                  spellCheck={false}
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                />
                <button type="submit" className="btn btn--primary">
                  Sign in
                </button>
              </div>
            </form>
          </>
        )}

        <footer className="auth-card__footer">
          <HealthIndicator state={health} />
          {health.kind === "error" && (
            <div role="alert" className="auth-card__error">
              <p>{health.message}</p>
              <p className="muted">
                Start it with <code>traceforge serve</code>.
              </p>
            </div>
          )}
          {health.kind !== "loading" && (
            <button type="button" className="btn btn--ghost btn--sm" onClick={onRetryHealth}>
              <Icon name="refresh" size={14} />
              Recheck
            </button>
          )}
        </footer>
      </main>
    </div>
  );
}
