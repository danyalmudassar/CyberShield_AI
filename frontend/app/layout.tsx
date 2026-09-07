import type { Metadata, Viewport } from "next";
import "./globals.css";
import { ThemeProvider } from "./theme-provider";

export const metadata: Metadata = {
  title: "CyberShield AI — PISF 2026 Security Audit Platform",
  description:
    "Professional cybersecurity audit platform following PISF 2026, PTES methodology, and OWASP Top 10. Powered by AI — Gemma4, Gemini, and Offline Rules Engine.",
  keywords: ["cybersecurity", "PISF 2026", "pentest", "security audit", "Pakistan", "OWASP"],
  authors: [{ name: "CyberShield AI" }],
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
};


export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
      </head>
      <body className="antialiased bg-[var(--background)] text-[var(--foreground)] transition-colors duration-200">
        <ThemeProvider attribute="class" defaultTheme="system" enableSystem>
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}
