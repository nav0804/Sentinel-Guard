import { Injectable, inject, OnDestroy } from '@angular/core';
import { BehaviorSubject } from 'rxjs';
import { webSocket, WebSocketSubject } from 'rxjs/webSocket';
import { filter, map, retry } from 'rxjs/operators';

export interface WafEvent {
  timestamp: number;
  ip: string;
  route: string;
  method: string;
  decision: 'SAFE' | 'MALICIOUS';
  reason: string;
  tier: number;
  time?: string; // Formatted time for display
}

export interface DashboardStats {
  total: number;
  blocked: number;
  allowed: number;
  byTier: Record<string, number>;
  recent: WafEvent[];
}

@Injectable({ providedIn: 'root' })
export class DashboardService implements OnDestroy {
  private statsSubject = new BehaviorSubject<DashboardStats>({
    total: 0,
    blocked: 0,
    allowed: 0,
    byTier: {},
    recent: [],
  });

  // This is what your component will subscribe to
  stats$ = this.statsSubject.asObservable();

  private socket: WebSocketSubject<any> | null = null;

  constructor() {
    this.connect();
  }

  private connect() {
    // Connect through the Angular proxy to avoid CORS issues
    this.socket = webSocket<any>({
      url: 'ws://localhost:4200/ws',
      deserializer: (e: MessageEvent) => JSON.parse(e.data),
      serializer: (value: any) => JSON.stringify(value),
    });

    this.socket
      .pipe(
        retry({ delay: 2000 }), // Auto-reconnect if proxy restarts
        filter((msg: any) => msg.type === 'event' || msg.type === 'init'),
        map((msg: any) => msg.data),
      )
      .subscribe({
        next: (data: any) => {
          if (data.type === 'init') {
            // Initial history load from backend
            this.statsSubject.next(data.stats);
          } else if (data.type === 'event') {
            // Real-time update
            this.updateStats(data.event);
          }
        },
        error: (err: any) => console.error('WebSocket error:', err),
      });
  }

  private updateStats(event: WafEvent) {
    const current = this.statsSubject.value;
    const isMalicious = event.decision === 'MALICIOUS';
    const tierName = `Tier ${event.tier}`;

    // Format timestamp nicely: "Nov 24, 1:51 AM"
    const date = new Date(event.timestamp);
    const timeString = date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });

    const formattedEvent: WafEvent = { ...event, time: timeString };

    this.statsSubject.next({
      total: current.total + 1,
      blocked: current.blocked + (isMalicious ? 1 : 0),
      allowed: current.allowed + (isMalicious ? 0 : 1),
      byTier: isMalicious
        ? { ...current.byTier, [tierName]: (current.byTier[tierName] || 0) + 1 }
        : current.byTier,
      // Add new attack to the TOP of the list, keep last 10
      recent: isMalicious ? [formattedEvent, ...current.recent].slice(0, 10) : current.recent,
    });
  }

  ngOnDestroy() {
    this.socket?.complete();
  }
}
