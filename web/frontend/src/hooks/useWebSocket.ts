/**
 * WebSocket hook for real-time scan updates
 */

import { useEffect, useRef, useState, useCallback } from 'react';
import type { WebSocketMessage } from '../types';

const WS_BASE_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000';

interface UseWebSocketOptions {
  onMessage?: (message: WebSocketMessage) => void;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
}

export function useWebSocket(scanId: number, options: UseWebSocketOptions = {}) {
  const {
    onMessage,
    reconnectInterval = 3000,
    maxReconnectAttempts = 5,
  } = options;

  const ws = useRef<WebSocket | null>(null);
  const reconnectCount = useRef(0);
  const reconnectTimeout = useRef<number>();
  
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null);

  const connect = useCallback(() => {
    try {
      const socket = new WebSocket(`${WS_BASE_URL}/ws/scans/${scanId}`);
      
      socket.onopen = () => {
        console.log(`WebSocket connected to scan ${scanId}`);
        setIsConnected(true);
        reconnectCount.current = 0;
      };

      socket.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data);
          setLastMessage(message);
          onMessage?.(message);
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };

      socket.onclose = () => {
        console.log(`WebSocket disconnected from scan ${scanId}`);
        setIsConnected(false);
        ws.current = null;

        // Auto-reconnect if not exceeding max attempts
        if (reconnectCount.current < maxReconnectAttempts) {
          reconnectCount.current++;
          console.log(`Reconnecting... (attempt ${reconnectCount.current}/${maxReconnectAttempts})`);
          
          reconnectTimeout.current = window.setTimeout(() => {
            connect();
          }, reconnectInterval);
        } else {
          console.error('Max reconnection attempts reached');
        }
      };

      socket.onerror = (error) => {
        console.error('WebSocket error:', error);
      };

      ws.current = socket;
    } catch (error) {
      console.error('Failed to create WebSocket connection:', error);
    }
  }, [scanId, onMessage, reconnectInterval, maxReconnectAttempts]);

  useEffect(() => {
    connect();

    return () => {
      // Cleanup on unmount
      if (reconnectTimeout.current) {
        clearTimeout(reconnectTimeout.current);
      }
      if (ws.current) {
        ws.current.close();
      }
    };
  }, [connect]);

  const sendMessage = useCallback((message: string) => {
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      ws.current.send(message);
    } else {
      console.warn('WebSocket is not connected');
    }
  }, []);

  return {
    isConnected,
    lastMessage,
    sendMessage,
  };
}
