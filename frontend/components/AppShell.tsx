"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { ReactNode, useEffect } from "react";
import { ROLE_LABELS, useAuth } from "@/lib/auth-context";

interface NavItem {
  href: string;
  label: string;
  roles?: string[];
}

const NAV_ITEMS: NavItem[] = [
  { href: "/dashboard", label: "Evidence" },
  { href: "/cases", label: "Cases" },
  { href: "/assets", label: "Physical Evidence" },
  { href: "/upload", label: "Upload", roles: ["investigating_officer", "forensics_officer", "admin"] },
  { href: "/audit", label: "Audit Ledger", roles: ["admin"] },
  { href: "/admin", label: "Administration", roles: ["admin"] },
  { href: "/security", label: "Security" },
];

export default function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { user, loading, signOut } = useAuth();

  useEffect(() => {
    if (loading) return;
    if (!user) {
      router.push("/login");
      return;
    }
    // A privileged account that has not finished enrolling can only reach
    // /security, which is where enrollment happens.
    if (user.mfa_enrollment_required && pathname !== "/security") {
      router.push("/security");
    }
  }, [loading, user, pathname, router]);

  if (loading || !user) return null;

  const items = NAV_ITEMS.filter((item) => !item.roles || item.roles.includes(user.role));

  return (
    <div className="min-h-screen flex flex-col">
      <header
        className="flex items-center justify-between px-8"
        style={{ height: 80, background: "var(--color-slate-dark)", color: "#fff" }}
      >
        <div>
          <div style={{ fontSize: 24, fontWeight: 800, letterSpacing: "-0.01em" }}>NYAYVAULT</div>
          <div className="label-bold" style={{ color: "var(--color-outline-variant)" }}>
            Case Records &amp; Integrity Verification
          </div>
        </div>
        <div className="flex items-center gap-6">
          <div style={{ textAlign: "right" }}>
            <div style={{ fontSize: 18, fontWeight: 700 }}>{user.full_name}</div>
            <div className="label-bold" style={{ color: "var(--color-outline-variant)" }}>
              {user.badge_number} · {ROLE_LABELS[user.role] ?? user.role}
            </div>
          </div>
          <button
            onClick={signOut}
            className="btn-secondary"
            style={{
              background: "transparent",
              color: "#fff",
              borderColor: "#fff",
              minHeight: 48,
              padding: "0 24px",
              fontSize: 16,
            }}
          >
            Sign Out
          </button>
        </div>
      </header>

      <div className="flex flex-1">
        <nav
          style={{
            width: 280,
            background: "var(--color-surface-container-low)",
            borderRight: "2px solid var(--color-border-heavy)",
          }}
          className="flex-shrink-0"
        >
          <ul>
            {items.map((item) => {
              const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    className="block"
                    style={{
                      padding: "20px 24px",
                      fontSize: 18,
                      fontWeight: active ? 700 : 500,
                      borderLeft: active
                        ? "4px solid var(--color-kinetic-blue)"
                        : "4px solid transparent",
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

          {!user.signing_key_fingerprint && !user.mfa_enrollment_required && (
            <div
              style={{
                margin: 24,
                padding: 16,
                border: "2px solid var(--color-status-warning)",
                background: "#fff4e5",
                fontSize: 16,
              }}
            >
              <strong>No signing key on this device.</strong> Uploads and custody transfers
              need one — set it up under Security.
            </div>
          )}
        </nav>

        <main className="flex-1 p-8">{children}</main>
      </div>
    </div>
  );
}
