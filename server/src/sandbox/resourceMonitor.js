/**
 * Resource Monitor Module
 * 
 * Real-time monitoring of resource consumption during code execution.
 * Polls CPU and memory usage at configured intervals and emits events
 * when thresholds are exceeded.
 */

import pidusage from 'pidusage';
import { EventEmitter } from 'events';

export class ResourceMonitor extends EventEmitter {
  constructor(options = {}) {
    super();
    this.pid = null;
    this.pollIntervalMs = options.pollIntervalMs || 200;
    this.memoryLimitMb = options.memoryLimitMb || 128;
    this.cpuWarningThreshold = options.cpuWarningThreshold || 90;
    this.memoryWarningMb = options.memoryWarningMb || null;
    this.samples = [];
    this.pollingTimer = null;
    this.startTime = null;
    this.maxMemoryMb = 0;
    this.maxCpuPercent = 0;
    this.warningsEmitted = new Set();
    this.killed = false;
  }

  /**
   * Start monitoring a process
   * @param {number} pid - Process ID to monitor
   */
  start(pid) {
    this.pid = pid;
    this.startTime = Date.now();
    this.samples = [];
    this.maxMemoryMb = 0;
    this.maxCpuPercent = 0;
    this.warningsEmitted.clear();
    this.killed = false;

    if (!this.memoryWarningMb) {
      this.memoryWarningMb = this.memoryLimitMb * 0.75;
    }

    this.pollingTimer = setInterval(() => {
      this._pollUsage();
    }, this.pollIntervalMs);

    // First poll immediately
    this._pollUsage();
  }

  /**
   * Stop monitoring
   */
  stop() {
    if (this.pollingTimer) {
      clearInterval(this.pollingTimer);
      this.pollingTimer = null;
    }
  }

  /**
   * Poll current resource usage
   */
  async _pollUsage() {
    if (!this.pid || this.killed) return;

    try {
      const stats = await pidusage(this.pid);
      if (!stats) return;

      const elapsedMs = Date.now() - this.startTime;
      const memoryMb = stats.memory / (1024 * 1024);
      const cpuPercent = stats.cpu;

      // Track maximums
      if (memoryMb > this.maxMemoryMb) this.maxMemoryMb = memoryMb;
      if (cpuPercent > this.maxCpuPercent) this.maxCpuPercent = cpuPercent;

      const sample = {
        timestamp_ms: elapsedMs,
        cpu_percent: Math.round(cpuPercent * 100) / 100,
        memory_mb: Math.round(memoryMb * 100) / 100,
        memory_rss_mb: Math.round(memoryMb * 100) / 100,
      };

      this.samples.push(sample);

      // Emit resource update
      this.emit('resource', sample);

      // Check memory warning threshold
      if (memoryMb > this.memoryWarningMb && !this.warningsEmitted.has('memory_warning')) {
        this.warningsEmitted.add('memory_warning');
        this.emit('warning', {
          type: 'memory_warning',
          message: `Memory usage at ${memoryMb.toFixed(1)}MB (warning threshold: ${this.memoryWarningMb}MB)`,
          current: memoryMb,
          threshold: this.memoryWarningMb
        });
      }

      // Check memory KILL threshold
      if (memoryMb > this.memoryLimitMb) {
        this.killed = true;
        this.emit('kill', {
          type: 'memory_exceeded',
          message: `Memory limit exceeded: ${memoryMb.toFixed(1)}MB > ${this.memoryLimitMb}MB`,
          current: memoryMb,
          limit: this.memoryLimitMb
        });
        this.stop();
        return;
      }

      // Check CPU warning
      if (cpuPercent > this.cpuWarningThreshold && !this.warningsEmitted.has('cpu_warning')) {
        this.warningsEmitted.add('cpu_warning');
        this.emit('warning', {
          type: 'cpu_warning',
          message: `CPU usage at ${cpuPercent.toFixed(1)}% (threshold: ${this.cpuWarningThreshold}%)`,
          current: cpuPercent,
          threshold: this.cpuWarningThreshold
        });
      }

    } catch (err) {
      // Process might have ended
      if (err.message && (err.message.includes('No matching pid') || err.message.includes('No such process'))) {
        this.stop();
      }
    }
  }

  /**
   * Get all collected samples
   */
  getSamples() {
    return this.samples;
  }

  /**
   * Get summary statistics
   */
  getSummary() {
    return {
      sampleCount: this.samples.length,
      maxMemoryMb: Math.round(this.maxMemoryMb * 100) / 100,
      maxCpuPercent: Math.round(this.maxCpuPercent * 100) / 100,
      memoryLimitMb: this.memoryLimitMb,
      durationMs: this.startTime ? Date.now() - this.startTime : 0,
      killed: this.killed,
    };
  }
}
