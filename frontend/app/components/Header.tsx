"use client";
import { useEffect, useState } from "react";
import {
  ShieldCheck,
  LayoutDashboard,
  FileText,
  ScanEye,
  ShieldAlert,
  ClipboardCheck,
  Sun,
  Moon,
  LogOut,
  ArrowUpRight,
} from "lucide-react";
import { useTheme } from "next-themes";
import Link from "next/link";
export type TabId = "overview" | "pisf" | "visual" | "findings" | "report";
export const navigation = [
  { id: "overview" as TabId, label: "Overview", icon: LayoutDashboard },
  { id: "findings" as TabId, label: "Findings", icon: ShieldAlert },
  { id: "visual" as TabId, label: "Web audit", icon: ScanEye },
  { id: "pisf" as TabId, label: "Compliance", icon: ClipboardCheck },
  { id: "report" as TabId, label: "Reports", icon: FileText },
];
export default function Header({
  activeTab,
  onSelectTab,
  authUser,
  onLogout,
}: {
  activeTab: TabId;
  onSelectTab: (tab: TabId) => void;
  authUser: { email: string; role: string };
  onLogout: () => void;
}) {
  const { resolvedTheme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  return (
    <>
      <a className="skip-link" href="#workspace">
        Skip to workspace
      </a>
      <aside className="sidebar">
        <Link href="/" className="brand">
          <span className="brand-mark">
            <ShieldCheck size={23} />
          </span>
          <span>
            CyberShield<span className="brand-ai">AI</span>
            <small>SECURITY WORKSPACE</small>
          </span>
        </Link>
        <div className="sidebar-section">WORKSPACE</div>
        <nav aria-label="Workspace navigation" className="side-navigation">
          {navigation.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => onSelectTab(id)}
              aria-current={activeTab === id ? "page" : undefined}
              className={activeTab === id ? "selected" : ""}
            >
              <Icon size={18} />
              <span>{label}</span>
              {activeTab === id && <span className="nav-indicator" />}
            </button>
          ))}
        </nav>
        <div className="sidebar-note">
          <ShieldCheck size={21} />
          <strong>Evidence comes first.</strong>
          <p>Review findings, their source and assessment coverage together.</p>
          <a
            href="https://pkcert.gov.pk/grc-policies.asp"
            target="_blank"
            rel="noopener noreferrer"
          >
            Framework reference <ArrowUpRight size={14} />
          </a>
        </div>
        <div className="sidebar-bottom">
          <span className="avatar">
            {authUser.email.slice(0, 2).toUpperCase()}
          </span>
          <div className="user-details">
            <strong>{authUser.email.split("@")[0]}</strong>
            <small>{authUser.role}</small>
          </div>
          <button
            className="icon-button"
            onClick={onLogout}
            aria-label="Sign out"
            title="Sign out"
          >
            <LogOut size={17} />
          </button>
        </div>
      </aside>
      <header className="workspace-header">
        <div>
          <span className="header-breadcrumb">Workspace</span>
          <span className="breadcrumb-divider">/</span>
          <strong>{navigation.find((n) => n.id === activeTab)?.label}</strong>
        </div>
        <div className="header-tools">
          <span className="access-badge">
            <ShieldCheck size={14} /> Authorized workspace
          </span>
          <button
            className="icon-button"
            aria-label="Toggle color theme"
            onClick={() =>
              setTheme(resolvedTheme === "dark" ? "light" : "dark")
            }
          >
            {mounted && resolvedTheme === "dark" ? (
              <Sun size={18} />
            ) : (
              <Moon size={18} />
            )}
          </button>
          <button
            className="icon-button mobile-logout"
            aria-label="Sign out"
            onClick={onLogout}
          >
            <LogOut size={18} />
          </button>
        </div>
      </header>
    </>
  );
}
