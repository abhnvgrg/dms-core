"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ApiError, login } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { Alert, Field } from "@/components/ui";

export default function LoginPage() {
  const router = useRouter();
  const { user, loading: authLoading, signIn } = useAuth();

  const [badgeNumber, setBadgeNumber] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!authLoading && user) router.push(user.mfa_enrollment_required ? "/security" : "/dashboard");
  }, [authLoading, user, router]);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError("");
    setSubmitting(true);

    try {
      const response = await login(badgeNumber, password, totpCode || undefined);
      signIn(response);
      router.push(response.mfa_enrollment_required ? "/security" : "/dashboard");
    } catch (err) {
      const message = err instanceof Error ? err.message : "Login failed";
      // The backend tells us a second factor is needed by rejecting the
      // password-only attempt; surface the code field rather than a dead end.
      if (message.toLowerCase().includes("mfa")) setMfaRequired(true);
      setError(message);
      if (err instanceof ApiError && err.status === 429) {
        setError(`${message} Repeated failures back off exponentially.`);
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div
      className="min-h-screen flex items-center justify-center"
      style={{ background: "var(--color-surface)", padding: 24 }}
    >
      <div style={{ width: "100%", maxWidth: 480 }}>
        <div style={{ marginBottom: 32 }}>
          <div style={{ fontSize: 32, fontWeight: 800, letterSpacing: "-0.01em" }}>NYAYVAULT</div>
          <p style={{ fontSize: 18, color: "var(--color-on-surface-variant)" }}>
            Secure evidence management. Sign in with your badge number.
          </p>
        </div>

        <div className="card" style={{ padding: 32 }}>
          {error && <Alert kind="error">{error}</Alert>}

          <form onSubmit={handleSubmit}>
            <Field label="Badge number">
              <input
                className="input-field"
                value={badgeNumber}
                onChange={(e) => setBadgeNumber(e.target.value)}
                autoComplete="username"
                required
              />
            </Field>

            <Field label="Password">
              <input
                className="input-field"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
              />
            </Field>

            {mfaRequired && (
              <Field
                label="Authenticator code"
                hint="Six digits from the authenticator app you enrolled."
              >
                <input
                  className="input-field data-mono"
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  autoFocus
                />
              </Field>
            )}

            <button type="submit" className="btn-primary" style={{ width: "100%" }} disabled={submitting}>
              {submitting ? "Signing in…" : "Sign In"}
            </button>
          </form>

          {!mfaRequired && (
            <button
              type="button"
              onClick={() => setMfaRequired(true)}
              style={{
                marginTop: 16,
                fontSize: 16,
                fontWeight: 600,
                background: "none",
                border: "none",
                color: "var(--color-kinetic-blue)",
                cursor: "pointer",
                padding: 0,
              }}
            >
              I have an authenticator code
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
