"use client";

import { GatewayHome } from "./console/auth";
import { LanguageProvider } from "./i18n";

export default function Home() {
  return (
    <LanguageProvider>
      <GatewayHome />
    </LanguageProvider>
  );
}
