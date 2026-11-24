import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { DashboardService, DashboardStats } from './dashboard.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './app.html',
  styleUrl: './app.scss',
})
export class AppComponent {
  private service = inject(DashboardService);

  // Async pipe will handle the real-time RxJS stream automatically
  stats$ = this.service.stats$;

  // 🛠️ NEW: Helper method for the template to iterate over object keys
  objectKeys(obj: any): string[] {
    return obj ? Object.keys(obj) : [];
  }

  getBlockRate(stats: DashboardStats | null): string {
    if (!stats || stats.total === 0) return '0.0';
    return ((stats.blocked / stats.total) * 100).toFixed(1);
  }

  getTierPercentage(count: number, totalBlocked: number): string {
    if (totalBlocked === 0) return '0';
    return ((count / totalBlocked) * 100).toFixed(0);
  }
}
