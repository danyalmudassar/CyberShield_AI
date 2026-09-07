import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  distDir: process.env.CYBERSHIELD_NEXT_DIST_DIR || ".next",
  async rewrites() {
    const backend = (process.env.CYBERSHIELD_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");
    return [{ source: "/api/:path*", destination: `${backend}/api/:path*` }];
  },
};

export default nextConfig;
