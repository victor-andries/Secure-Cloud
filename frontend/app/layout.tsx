import type { Metadata } from "next";
import "./globals.css";
import Providers from "@/app/providers";
import Navbar from "@/components/Navbar";

export const metadata: Metadata = {
  title: "Secure Cloud Platform",
  description: "Blockchain-secured, AI-monitored encrypted cloud storage",
  icons: {
    icon: "/favicon.ico"
  }
};

export default function RootLayout({
  children
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[#0f0f1a] text-gray-100">
        <Providers>
          <Navbar />
          <main className="pt-16 min-h-screen">
            {children}
          </main>
        </Providers>
      </body>
    </html>
  );
}
