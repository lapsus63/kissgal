import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class ThemeService {
  private darkMode = new BehaviorSubject<boolean>(this.isDarkMode());
  darkMode$ = this.darkMode.asObservable();

  private isDarkMode(): boolean {
    const savedMode = localStorage.getItem('darkMode');
    if (savedMode) {
      return savedMode === 'true';
    }
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  }

  toggleDarkMode(): void {
    const isDark = !this.darkMode.value;
    this.darkMode.next(isDark);
    localStorage.setItem('darkMode', isDark.toString());
    if (isDark) {
      document.body.classList.add('dark-mode');
    } else {
      document.body.classList.remove('dark-mode');
    }
  }

  initializeTheme(): void {
    if (this.darkMode.value) {
      document.body.classList.add('dark-mode');
    }
  }
}
