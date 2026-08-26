"use client";

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useSyncExternalStore,
  ReactNode,
} from "react";
import { useRouter } from "next/navigation";
import {
  CurrentUser,
  LoginResponse,
  clearToken,
  fetchMe,
  logout as apiLogout,
  setTokens,
} from "./api";

export interface AuthUser {
  id: string;
  full_name: string;
  role: string;
  badge_number: string;
  mfa_enabled: boolean;
  signing_key_fingerprint: string | null;
  /** True while a privileged account still has to finish enrolling MFA. */
  mfa_enrollment_required: boolean;
}

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  signIn: (response: LoginResponse) => void;
  signOut: () => void;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);
const USER_KEY = "dms_user";
const CHANGED_EVENT = "nyayvault:auth-changed";

/**
 * The stored session is an external store, not React state: it is written by
 * the API layer on refresh, by other tabs, and by sign-in. Subscribing to it
 * keeps every tab consistent and avoids re-deriving it in an effect.
 */
function subscribe(onChange: () => void) {
  window.addEventListener("storage", onChange);
  window.addEventListener(CHANGED_EVENT, onChange);
  return () => {
    window.removeEventListener("storage", onChange);
    window.removeEventListener(CHANGED_EVENT, onChange);
  };
}

function readStoredUser(): string | null {
  try {
    return localStorage.getItem(USER_KEY);
  } catch {
    return null;
  }
}

function announceChange() {
  window.dispatchEvent(new Event(CHANGED_EVENT));
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const router = useRouter();

  // null on the server and during hydration, then the real value.
  const storedUser = useSyncExternalStore(subscribe, readStoredUser, () => null);
  const hydrated = useSyncExternalStore(
    subscribe,
    () => true,
    () => false,
  );

  const user = useMemo<AuthUser | null>(() => {
    if (!storedUser) return null;
    try {
      return JSON.parse(storedUser) as AuthUser;
    } catch {
      return null;
    }
  }, [storedUser]);

  const signIn = useCallback((response: LoginResponse) => {
    setTokens(response.access_token, response.refresh_token);
    const next: AuthUser = {
      id: "",
      full_name: response.full_name,
      role: response.role,
      badge_number: response.badge_number,
      mfa_enabled: response.mfa_enabled,
      signing_key_fingerprint: null,
      mfa_enrollment_required: response.mfa_enrollment_required,
    };
    localStorage.setItem(USER_KEY, JSON.stringify(next));
    announceChange();
  }, []);

  const signOut = useCallback(() => {
    void apiLogout();
    clearToken();
    announceChange();
    router.push("/login");
  }, [router]);

  /** Re-read the profile after enrolling MFA or registering a signing key. */
  const refreshUser = useCallback(async () => {
    try {
      const me: CurrentUser = await fetchMe();
      const previous = readStoredUser();
      const wasPending = previous
        ? (JSON.parse(previous) as AuthUser).mfa_enrollment_required
        : false;

      const next: AuthUser = {
        id: me.id,
        full_name: me.full_name,
        role: me.role,
        badge_number: me.badge_number,
        mfa_enabled: me.mfa_enabled,
        signing_key_fingerprint: me.signing_key_fingerprint,
        mfa_enrollment_required: wasPending ? !me.mfa_enabled : false,
      };
      localStorage.setItem(USER_KEY, JSON.stringify(next));
      announceChange();
    } catch {
      // A failure here means the session is gone; the API layer handles that.
    }
  }, []);

  const value = useMemo(
    () => ({ user, loading: !hydrated, signIn, signOut, refreshUser }),
    [user, hydrated, signIn, signOut, refreshUser],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

export function isAdmin(user: AuthUser | null): boolean {
  return user?.role === "admin";
}

export function canUpload(user: AuthUser | null): boolean {
  return (
    user?.role === "investigating_officer" ||
    user?.role === "forensics_officer" ||
    user?.role === "admin"
  );
}

export const ROLE_LABELS: Record<string, string> = {
  investigating_officer: "Investigating Officer",
  forensics_officer: "Forensics Officer",
  court_official: "Court Official",
  admin: "Administrator",
};
