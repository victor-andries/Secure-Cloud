"use client";

import UploadZone from "@/components/UploadZone";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { useUpload } from "./_hooks/useUpload";
import UploadResult from "./_components/UploadResult";

export default function UploadPage() {
  const {
    address, file, password, confirmPassword,
    uploading, progress, result, error,
    pwMatch, pwMismatch,
    handleFileSelect, handleSubmit,
    setPassword, setConfirmPassword,
  } = useUpload();

  return (
    <div className="max-w-2xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-3">
          <span className="section-label">Secure Storage</span>
          <div className="flex-1 h-px bg-border" />
        </div>
        <h1 className="font-heading text-4xl font-bold tracking-tight">
          Secure <span className="text-primary">Upload</span>
        </h1>
        <p className="text-muted-foreground mt-2 text-sm">
          Files are chunked, encrypted, and registered on-chain
        </p>
      </div>

      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <UploadZone onFileSelect={handleFileSelect} selectedFile={file} disabled={uploading} />

        <Card>
          <CardContent className="p-6 flex flex-col gap-4">
            <div className="flex items-center gap-3">
              <span className="section-label">Encryption Password</span>
              <div className="flex-1 h-px bg-border" />
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-sm text-muted-foreground" htmlFor="password">
                Password <span className="text-red-500">*</span>
              </label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Min. 8 characters"
                disabled={uploading}
                className={cn(
                  "w-full px-3 py-2.5 text-sm bg-muted border text-foreground placeholder-muted-foreground",
                  "focus:outline-none focus:border-primary/60 transition-colors disabled:opacity-50 font-mono rounded-sm",
                  password.length > 0 && password.length < 8 ? "border-red-500/50" : "border-border"
                )}
              />
              {password.length > 0 && password.length < 8 && (
                <p className="font-mono text-xs text-red-400">Too short — minimum 8 characters</p>
              )}
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-sm text-muted-foreground" htmlFor="confirm-password">
                Confirm Password <span className="text-red-500">*</span>
              </label>
              <input
                id="confirm-password"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Repeat your password"
                disabled={uploading}
                className={cn(
                  "w-full px-3 py-2.5 text-sm bg-muted border text-foreground placeholder-muted-foreground",
                  "focus:outline-none focus:border-primary/60 transition-colors disabled:opacity-50 font-mono rounded-sm",
                  pwMismatch ? "border-red-500/50" : pwMatch ? "border-emerald-500/50" : "border-border"
                )}
              />
              {pwMismatch && <p className="font-mono text-xs text-red-400">Passwords do not match</p>}
              {pwMatch    && <p className="font-mono text-xs text-emerald-400">Passwords match</p>}
            </div>
          </CardContent>
        </Card>

        {!address && (
          <div className="flex items-start gap-3 p-4 border border-amber-500/20 bg-amber-500/5">
            <svg className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <p className="text-amber-400 text-sm">Connect your wallet to register the file on the blockchain.</p>
          </div>
        )}

        {uploading && (
          <div className="flex flex-col gap-2">
            <div className="flex justify-between items-center">
              <span className="font-mono text-xs text-muted-foreground">Encrypting & uploading…</span>
              <span className="font-mono text-xs text-primary">{progress}%</span>
            </div>
            <div className="h-1 bg-muted overflow-hidden">
              <div className="h-full bg-primary transition-all duration-500" style={{ width: `${progress}%` }} />
            </div>
          </div>
        )}

        {error && (
          <div className="flex items-start gap-3 p-4 border border-red-500/20 bg-red-500/5">
            <svg className="w-4 h-4 text-red-500 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <p className="text-red-400 text-sm">{error}</p>
          </div>
        )}

        <button
          type="submit"
          disabled={uploading || !file}
          className={cn(
            "w-full py-3 text-sm font-heading font-semibold tracking-wide transition-all duration-200",
            "bg-primary text-primary-foreground hover:bg-primary/90",
            "disabled:opacity-30 disabled:cursor-not-allowed"
          )}
        >
          {uploading ? "Uploading…" : "Encrypt & Upload"}
        </button>
      </form>

      {result && <UploadResult result={result} />}
    </div>
  );
}
