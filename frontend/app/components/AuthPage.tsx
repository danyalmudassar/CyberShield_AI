"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  ShieldCheck,
  ArrowRight,
  Eye,
  EyeOff,
  LockKeyhole,
  AlertCircle,
  ScanLine,
  Fingerprint,
  FileCheck2,
  LoaderCircle,
} from "lucide-react";
export default function AuthPage({ signup = false }: { signup?: boolean }) {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [visible, setVisible] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    fetch("/api/v1/auth/me", {
      credentials: "same-origin",
      cache: "no-store",
      signal: controller.signal,
    })
      .then((r) => {
        if (r.ok) router.replace("/");
      })
      .catch(() => {});
    return () => controller.abort();
  }, [router]);
  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (loading) return;
    if (signup && password !== confirmation) { setError("Passwords do not match."); return; }
    setLoading(true);
    setError("");
    try {
      const response = await fetch(signup ? "/api/v1/auth/register" : "/api/v1/auth/login", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CyberShield-Request": "1",
        },
        body: JSON.stringify({ email: email.trim(), password }),
      });
      const data = await response.json().catch(() => null);
      if (!response.ok)
        throw new Error(
          typeof data?.detail === "string"
            ? data.detail
            : "Unable to sign in. Check your credentials and try again.",
        );
      setPassword("");
      router.replace("/");
    } catch (failure) {
      setError(
        failure instanceof Error
          ? failure.message
          : "Unable to connect. Please try again.",
      );
      setLoading(false);
    }
  }
  return (
    <main className="login-page">
      <section className="login-story" aria-label="About CyberShield">
        <div className="brand">
          <span className="brand-mark">
            <ShieldCheck size={25} />
          </span>
          <span>
            CyberShield<span className="brand-ai">AI</span>
            <small>SECURITY WORKSPACE</small>
          </span>
        </div>
        <div className="login-story-content">
          <div className="eyebrow">
            <span /> CLARITY. CONFIDENCE. CONTROL.
          </div>
          <h1>
            See the risks.
            <br />
            Know your
            <br />
            <em>next move.</em>
          </h1>
          <p>
            A focused workspace for security assessments, evidence and
            actionable reports.
          </p>
          <div className="security-diagram" aria-hidden="true">
            <div className="diagram-orbit orbit-one" />
            <div className="diagram-orbit orbit-two" />
            <div className="diagram-core">
              <ShieldCheck size={48} strokeWidth={1.3} />
            </div>
            <span className="diagram-label label-one">
              <ScanLine size={17} /> Assess
            </span>
            <span className="diagram-label label-two">
              <Fingerprint size={17} /> Verify
            </span>
            <span className="diagram-label label-three">
              <FileCheck2 size={17} /> Report
            </span>
          </div>
        </div>
        <div className="login-story-footer">
          <span>Built for deliberate security decisions.</span>
          <span>CyberShield AI</span>
        </div>
      </section>
      <section className="login-form-panel">
        <div className="login-topline">
          <span>YOUR SECURITY WORKSPACE</span>
          <LockKeyhole size={17} />
        </div>
        <div className="login-form-wrap">
          <div className="login-form-icon">
            <Fingerprint size={28} />
          </div>
          <p className="eyebrow">{signup ? "GET STARTED" : "WELCOME BACK"}</p>
          <h2>{signup ? "Create your account" : "Sign in to CyberShield"}</h2>
          <p className="login-description">{signup ? "Your own workspace for assessments, evidence and reports. Create an operator account to begin." : "Your next assessment starts here. Use your workspace credentials to continue."}</p>
          <form onSubmit={submit} className="login-form" aria-busy={loading}>
            {error && (
              <div className="form-error" role="alert">
                <AlertCircle size={18} />
                <span>{error}</span>
              </div>
            )}
            <div>
              <label htmlFor="email">Work email</label>
              <input
                id="email"
                name="email"
                type="email"
                autoComplete="username"
                placeholder="you@organization.com"
                required
                disabled={loading}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
            <div>
              <label htmlFor="password">Password</label>
              <div className="password-field">
                <input
                  id="password"
                  name="password"
                  type={visible ? "text" : "password"}
                  autoComplete={signup ? "new-password" : "current-password"}
                    minLength={signup ? 12 : 1}
                    maxLength={256}
                  placeholder="Enter your password"
                  required
                  disabled={loading}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                <button
                  type="button"
                  aria-label={visible ? "Hide password" : "Show password"}
                  aria-pressed={visible}
                  onClick={() => setVisible(!visible)}
                >
                  {visible ? <EyeOff size={19} /> : <Eye size={19} />}
                </button>
              </div>
            </div>
            {signup && <div><label htmlFor="confirm-password">Confirm password</label><input id="confirm-password" name="confirm-password" type={visible ? "text" : "password"} autoComplete="new-password" minLength={12} maxLength={256} required disabled={loading} value={confirmation} onChange={e => setConfirmation(e.target.value)} placeholder="Re-enter your password"/><p className="password-guidance">Use at least 12 characters. A unique passphrase works well.</p></div>}
            <button
              type="submit"
              className="primary-button login-submit"
              disabled={loading}
            >
              {loading ? (
                <>
                  <LoaderCircle className="animate-spin" size={18} /> Signing
                  in…
                </>
              ) : (
                <>
                  {signup ? "Create account" : "Sign in to workspace"} <ArrowRight size={18} />
                </>
              )}
            </button>
          </form>
          <p className="auth-switch">{signup ? "Already have an account?" : "New to CyberShield?"} <Link href={signup ? "/login" : "/signup"}>{signup ? "Sign in" : "Create an account"}</Link></p>
          <p className="login-help">
            Need access or a password reset?
            <br />
            <strong>Contact your workspace administrator.</strong>
          </p>
          <div className="login-trust">
            <LockKeyhole size={15} />
            <span>Access is restricted to authorized users.</span>
          </div>
        </div>
        <footer className="login-footer">
          CyberShield AI <span>Security assessment & evidence management</span>
        </footer>
      </section>
    </main>
  );
}
