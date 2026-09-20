import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SB Gateway — управление VLESS на MikroTik",
  description:
    "Локальная защищённая панель управления маршрутизацией, VLESS, Cloudflare и отказоустойчивостью на MikroTik RouterOS.",
  robots: {
    index: false,
    follow: false,
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="ru">
      <body>{children}</body>
    </html>
  );
}
