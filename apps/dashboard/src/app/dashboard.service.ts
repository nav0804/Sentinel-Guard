import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, interval, switchMap, shareReplay } from 'rxjs';

export interface DashboardStats {
  total: number;
  blocked: number;
  allowed: number;
  byTier: Record<string, number>;
  recent: Array<{
    timestamp: number;
    time: string;
    ip: string;
    route: string;
    reason: string;
    tier: number;
  }>;
}

@Injectable({
  providedIn: 'root',
})
export class DashboardService {
  private http = inject(HttpClient);

  // Poll the API every 3 seconds for real-time updates
  stats$ = interval(3000).pipe(
    switchMap(() => this.http.get<DashboardStats>('/api/stats')),
    shareReplay(1),
  );
}
