// Machine description recorded with every result.
import { execFileSync } from 'node:child_process';
import { arch, availableParallelism, cpus, platform, release, totalmem, version } from 'node:os';

export interface MachineInfo {
  cpu_model: string;
  logical_cores: number;
  ram_bytes: number;
  os: string;
  arch: string;
  node: string;
  date: string;
  power_plan: string | null;
}

export function localDate(d = new Date()): string {
  const p = (n: number): string => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

function powerPlan(): string | null {
  if (platform() !== 'win32') return null;
  try {
    const out = execFileSync('powercfg', ['/getactivescheme'], { encoding: 'utf8', timeout: 5000, windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
    const m = /\(([^)]+)\)\s*$/m.exec(out.trim());
    return m?.[1] ?? out.trim().slice(0, 120);
  } catch {
    return null;
  }
}

export function machineInfo(now = new Date()): MachineInfo {
  return {
    cpu_model: cpus()[0]?.model.trim() ?? 'unknown',
    logical_cores: availableParallelism(),
    ram_bytes: totalmem(),
    os: `${platform()} ${release()} (${version()})`,
    arch: arch(),
    node: process.version,
    date: now.toISOString(),
    power_plan: powerPlan(),
  };
}
