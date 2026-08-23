"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { ReactNode } from "react";

const NAV_ITEMS = [
  { href: "/dashboard", label: "Evidence Dashboard" },
  { href: "/upload", label: "Upload Evidence" },
];

export default function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const { user, signOut } = useAuth();

  return (
    <div className="min-h-screen flex flex-col">
      <header
        className="flex items-center justify-between px-8"
        style={{ height: 80, background: "var(--color-slate-dark)", color: "#fff" }}
      >
        <div>
          <div style={{ fontSize: 24, fontWeight: 800, letterSpacing: "-0.01em" }}>
            NYAYVAULT
          </div>
          <div className="label-bold" style={{ color: "var(--color-outline-variant)" }}>
            Case Records &amp; Integrity Verification
          </div>
        </div>
        {user && (
          <div className="flex items-center gap-6">
            <div style={{ textAlign: "right" }}>
              <div style={{ fontSize: 18, fontWeight: 700 }}>{user.full_name}</div>
              <div className="label-bold" style={{ color: "var(--color-outline-variant)" }}>
                {user.role}
              </div>
            </div>
            <button
              onClick={signOut}
              className="btn-secondary"
              style={{ background: "transparent", color: "#fff", borderColor: "#fff", minHeight: 48, padding: "0 24px", fontSize: 16 }}
            >
              Sign Out
            </button>
          </div>
        )}
      </header>

      <div className="flex flex-1">
        <nav
          style={{ width: 280, background: "var(--color-surface-container-low)", borderRight: "2px solid var(--color-border-heavy)" }}
          className="flex-shrink-0"
        >
          <ul>
            {NAV_ITEMS.map((item) => {
              const active = pathname === item.href;
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    className="block"
                    style={{
                      padding: "20px 24px",
                      fontSize: 18,
                      fontWeight: active ? 700 : 500,
                      borderLeft: active ? "4px solid var(--color-kinetic-blue)" : "4px solid transparent",
                      background: active ? "var(--color-surface-container-lowest)" : "transparent",
                      color: "var(--color-on-surface)",
                    }}
                  >
                    {item.label}
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>

        <main className="flex-1 p-8">{children}</main>
      </div>
    </div>
  );
}
