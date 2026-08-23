"use client";

import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { useRouter } from "next/navigation";
import { setToken, clearToken } from "./api";

interface AuthUser {
  full_name: string;
  role: string;
  username: string;
}

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  signIn: (token: string, user: AuthUser) => void;
  signOut: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    const stored = localStorage.getItem("dms_user");
    if (stored) {
      try {
        setUser(JSON.parse(stored));
      } catch {
        // ignore malformed stored value
      }
    }
    setLoading(false);
  }, []);

  function signIn(token: string, newUser: AuthUser) {
    setToken(token);
    localStorage.setItem("dms_user", JSON.stringify(newUser));
    setUser(newUser);
  }

  function signOut() {
    clearToken();
    setUser(null);
    router.push("/login");
  }

  return (
    <AuthContext.Provider value={{ user, loading, signIn, signOut }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
