"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { login } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const { signIn } = useAuth();
  const router = useRouter();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const res = await login(username, password);
      signIn(res.access_token, {
        full_name: res.full_name,
        role: res.role,
        username,
      });
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div
      className="min-h-screen flex items-center justify-center"
      style={{ background: "var(--color-slate-dark)" }}
    >
      <div className="card" style={{ width: 480, borderColor: "#fff" }}>
        <div className="card-header" style={{ background: "var(--color-slate-dark)" }}>
          <div style={{ fontSize: 28, fontWeight: 800, color: "#fff" }}>
            NYAYVAULT
          </div>
          <div className="label-bold" style={{ color: "var(--color-outline-variant)", marginTop: 8 }}>
            Authorized Personnel Only
          </div>
        </div>

        <form onSubmit={handleSubmit} style={{ padding: 32 }}>
          <div style={{ marginBottom: 24 }}>
            <label className="label-bold" style={{ display: "block", marginBottom: 8 }}>
              Username
            </label>
            <input
              className="input-field"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="officer1"
              required
              autoFocus
            />
          </div>

          <div style={{ marginBottom: 24 }}>
            <label className="label-bold" style={{ display: "block", marginBottom: 8 }}>
              Password
            </label>
            <input
              className="input-field"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              required
            />
          </div>

          {error && (
            <div
              style={{
                background: "var(--color-error-container)",
                color: "var(--color-on-error-container)",
                padding: 16,
                marginBottom: 24,
                fontWeight: 600,
                fontSize: 16,
                border: "2px solid var(--color-error)",
              }}
            >
              {error}
            </div>
          )}

          <button type="submit" className="btn-primary" style={{ width: "100%" }} disabled={submitting}>
            {submitting ? "Signing In..." : "Sign In"}
          </button>
        </form>
      </div>
    </div>
  );
}
