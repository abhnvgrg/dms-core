"use client";

import { useEffect, useRef, useState, useSyncExternalStore } from "react";

/**
 * QR scanning through the browser's own BarcodeDetector, with manual entry as
 * the fallback. No third-party scanner library, and nothing leaves the device.
 */

interface DetectedBarcode {
  rawValue: string;
}

interface BarcodeDetectorLike {
  detect: (source: CanvasImageSource) => Promise<DetectedBarcode[]>;
}

declare global {
  interface Window {
    BarcodeDetector?: new (options?: { formats: string[] }) => BarcodeDetectorLike;
  }
}

const UUID_PATTERN = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

export default function QrScanner({ onScan }: { onScan: (qrUuid: string) => void }) {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const [manual, setManual] = useState("");

  // Whether the browser can decode barcodes is a property of the platform, not
  // React state, so it is read as an external snapshot rather than in an effect.
  const supported = useSyncExternalStore(
    () => () => {},
    () => typeof window.BarcodeDetector === "function",
    () => false,
  );

  useEffect(() => {
    return () => {
      streamRef.current?.getTracks().forEach((track) => track.stop());
    };
  }, []);

  async function start() {
    setError("");
    if (!window.BarcodeDetector) {
      setError("This browser has no barcode detector. Type the tag id instead.");
      return;
    }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
      streamRef.current = stream;
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        await videoRef.current.play();
      }
      setScanning(true);

      const detector = new window.BarcodeDetector({ formats: ["qr_code"] });

      const tick = async () => {
        if (!videoRef.current || !streamRef.current) return;
        try {
          const codes = await detector.detect(videoRef.current);
          const match = codes.map((code) => code.rawValue).find((value) => UUID_PATTERN.test(value));
          if (match) {
            stop();
            onScan(UUID_PATTERN.exec(match)![0]);
            return;
          }
        } catch {
          // A frame that fails to decode is normal; keep going.
        }
        requestAnimationFrame(() => void tick());
      };

      void tick();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not open the camera");
    }
  }

  function stop() {
    streamRef.current?.getTracks().forEach((track) => track.stop());
    streamRef.current = null;
    setScanning(false);
  }

  return (
    <div>
      <div className="flex gap-4" style={{ marginBottom: 16 }}>
        {scanning ? (
          <button type="button" className="btn-secondary" onClick={stop}>
            Stop camera
          </button>
        ) : (
          <button type="button" className="btn-secondary" onClick={start} disabled={!supported}>
            {supported ? "Scan tag with camera" : "Camera scanning unavailable"}
          </button>
        )}
      </div>

      {error && (
        <p style={{ color: "var(--color-on-error-container)", fontWeight: 600, marginBottom: 16 }}>
          {error}
        </p>
      )}

      <video
        ref={videoRef}
        muted
        playsInline
        style={{
          display: scanning ? "block" : "none",
          width: "100%",
          maxWidth: 420,
          border: "2px solid var(--color-slate-dark)",
          marginBottom: 16,
        }}
      />

      <div className="flex gap-4 items-end" style={{ maxWidth: 560 }}>
        <div style={{ flex: 1 }}>
          <label className="label-bold" style={{ display: "block", marginBottom: 8 }}>
            Or enter the tag id
          </label>
          <input
            className="input-field data-mono"
            value={manual}
            onChange={(e) => setManual(e.target.value)}
            placeholder="00000000-0000-0000-0000-000000000000"
          />
        </div>
        <button
          type="button"
          className="btn-secondary"
          onClick={() => UUID_PATTERN.test(manual) && onScan(manual.trim())}
          disabled={!UUID_PATTERN.test(manual)}
        >
          Look up
        </button>
      </div>
    </div>
  );
}
