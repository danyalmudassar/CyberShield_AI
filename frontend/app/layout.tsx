import type { Metadata, Viewport } from "next";
import "./globals.css";
import { ThemeProvider } from "./theme-provider";

export const metadata: Metadata = {
  title: "CyberShield AI — Security Workspace",
  description:
    "Security assessment workspace for scoped scans, evidence review and technical compliance mapping.",
  keywords: [
    "cybersecurity",
    "PISF 2026",
    "pentest",
    "security audit",
    "Pakistan",
    "OWASP",
  ],
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
      <body className="antialiased bg-[var(--background)] text-[var(--foreground)] transition-colors duration-200">
        <ThemeProvider attribute="class" defaultTheme="light" enableSystem>
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}
