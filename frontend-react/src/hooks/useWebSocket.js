import { useEffect, useRef } from 'react';
import io from 'socket.io-client';
import { WS_URL } from '../utils/constants';

/**
 * Connects to Flask-SocketIO and wires up event callbacks.
 * Returns the socket instance (stable ref).
 *
 * Events from backend:
 *   new_event          — new network event recorded
 *   anomaly_detected   — ML flagged an anomaly
 *   new_isolation      — a device was just isolated
 *   summary_update     — dashboard counts changed
 *   ml_score           — ML inference score for a device
 */
export function useWebSocket({
  onNewEvent,
  onAnomalyDetected,
  onIsolation,
  onSummaryUpdate,
  onMLScore,
  onStatusChange,
} = {}) {
  const socketRef = useRef(null);

  useEffect(() => {
    const socket = io(WS_URL, {
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: 10,
    });

    socketRef.current = socket;

    socket.on('connect', () => {
      console.log('[WS] Connected');
      onStatusChange?.('connected');
    });

    socket.on('disconnect', () => {
      console.log('[WS] Disconnected');
      onStatusChange?.('disconnected');
    });

    socket.on('new_event',        (d) => onNewEvent?.(d));
    socket.on('anomaly_detected', (d) => onAnomalyDetected?.(d));
    socket.on('new_isolation',    (d) => onIsolation?.(d));
    socket.on('summary_update',   (d) => onSummaryUpdate?.(d));
    socket.on('ml_score',         (d) => onMLScore?.(d));

    return () => socket.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return socketRef;
}
