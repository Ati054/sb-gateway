import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: process.env.SB_BUILD_TARGET === "sites" ? undefined : "export",
  images: {
    unoptimized: true,
  },
};

export default nextConfig;
