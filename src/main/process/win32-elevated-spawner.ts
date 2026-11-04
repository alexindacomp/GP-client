import { execFile } from 'node:child_process';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import net from 'node:net';
import path from 'node:path';
import { SYSTEM_PS_MODULES, WINDOWS_POWERSHELL } from '../openconnect/windows-acl';
import { quoteWindowsArg } from './elevation';
import { BaseVpnProcess, SpawnError, type ProcessSpawner, type SpawnRequest } from './types';

/**
 * Elevated bridge (runs as administrator after the UAC prompt). Connects back to
 * the app over a named pipe, authenticates with a one-time token, starts
 * openconnect with redirected stdio and relays it as base64 frames:
 *   bridge → app: H:<token>  P:<pid>  O:<b64 stdout>  E:<b64 stderr>  X:<exit code>
 *   app → bridge: I:<b64 stdin>  S (Ctrl+C)  K (kill)
 * Closing the pipe from the app side kills openconnect, so it never outlives the app.
 */
const BRIDGE_SCRIPT = String.raw`
# Only modules shipped with Windows: the default PSModulePath starts with the
# user's (writable) Documents folder, which would allow cmdlet hijacking.
$env:PSModulePath = "$PSHOME\Modules"
$ErrorActionPreference = 'Stop'
$cfgPath = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CONFIG_PATH__'))
$bytes = [IO.File]::ReadAllBytes($cfgPath)
Remove-Item -LiteralPath $cfgPath -Force
$hash = -join ([Security.Cryptography.SHA256]::Create().ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
if ($hash -ne '__CONFIG_SHA256__') { exit 3 }
$cfg = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
# Add-Type compiles via csc.exe in %TEMP%. The user's %TEMP% is writable by
# unprivileged processes (race -> code execution as admin), so compile in a fresh
# directory under ProgramData that only SYSTEM and Administrators can access.
$pd = [Environment]::GetFolderPath('CommonApplicationData')
if (-not $pd) { exit 4 }
$tmp = Join-Path $pd ('GP-Connect-' + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $tmp) { exit 4 }
$ds = New-Object System.Security.AccessControl.DirectorySecurity
$ds.SetAccessRuleProtection($true, $false)
foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
  $id = New-Object System.Security.Principal.SecurityIdentifier($sid)
  $ds.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
$ds.SetOwner((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')))
$null = [System.IO.Directory]::CreateDirectory($tmp, $ds)
$oldTemp = $env:TEMP; $oldTmp = $env:TMP
$env:TEMP = $tmp; $env:TMP = $tmp
try {
  Add-Type -Namespace GpConnect -Name Con -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern bool GenerateConsoleCtrlEvent(uint e, uint g);
[DllImport("kernel32.dll")] public static extern bool SetConsoleCtrlHandler(System.IntPtr h, bool add);
'@
} finally {
  $env:TEMP = $oldTemp; $env:TMP = $oldTmp
  Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', $cfg.pipe, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous)
$pipe.Connect(30000)
$enc = New-Object System.Text.UTF8Encoding($false)
$w = New-Object System.IO.StreamWriter($pipe, $enc)
$w.AutoFlush = $true
$w.NewLine = [string][char]10
$r = New-Object System.IO.StreamReader($pipe, $enc)
$w.WriteLine('H:' + $cfg.token)
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $cfg.exe
$psi.Arguments = $cfg.args
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
try { $p = [System.Diagnostics.Process]::Start($psi) } catch { $w.WriteLine('E:' + [Convert]::ToBase64String($enc.GetBytes($_.Exception.Message + [char]10))); $w.WriteLine('X:127'); exit 1 }
$w.WriteLine('P:' + $p.Id)
[GpConnect.Con]::SetConsoleCtrlHandler([System.IntPtr]::Zero, $true) | Out-Null
$ob = New-Object byte[] 8192; $eb = New-Object byte[] 8192
$ot = $p.StandardOutput.BaseStream.ReadAsync($ob, 0, $ob.Length)
$et = $p.StandardError.BaseStream.ReadAsync($eb, 0, $eb.Length)
$lt = $r.ReadLineAsync()
$od = $false; $ed = $false
while ($true) {
  $busy = $false
  if (-not $od -and $ot.IsCompleted) { $n = $ot.Result; if ($n -le 0) { $od = $true } else { $w.WriteLine('O:' + [Convert]::ToBase64String($ob, 0, $n)); $ot = $p.StandardOutput.BaseStream.ReadAsync($ob, 0, $ob.Length); $busy = $true } }
  if (-not $ed -and $et.IsCompleted) { $n = $et.Result; if ($n -le 0) { $ed = $true } else { $w.WriteLine('E:' + [Convert]::ToBase64String($eb, 0, $n)); $et = $p.StandardError.BaseStream.ReadAsync($eb, 0, $eb.Length); $busy = $true } }
  if ($lt -ne $null -and $lt.IsCompleted) {
    $line = $null
    if (-not $lt.IsFaulted) { $line = $lt.Result }
    if ($line -eq $null) { if (-not $p.HasExited) { $p.Kill() }; $lt = $null }
    else {
      if ($line.StartsWith('I:')) { $b = [Convert]::FromBase64String($line.Substring(2)); $p.StandardInput.BaseStream.Write($b, 0, $b.Length); $p.StandardInput.BaseStream.Flush() }
      elseif ($line -eq 'S') { [GpConnect.Con]::GenerateConsoleCtrlEvent(0, 0) | Out-Null }
      elseif ($line -eq 'K') { if (-not $p.HasExited) { $p.Kill() } }
      $lt = $r.ReadLineAsync()
      $busy = $true
    }
  }
  if ($od -and $ed -and $p.HasExited) { break }
  if (-not $busy) { Start-Sleep -Milliseconds 20 }
}
$p.WaitForExit()
try { $w.WriteLine('X:' + $p.ExitCode) } catch {}
$pipe.Dispose()
`;

const CONNECT_TIMEOUT_MS = 3 * 60_000; // includes the time the user looks at the UAC dialog

/** Hard-coded: %SystemRoot% comes from the (attacker-influenceable) environment. */
function powershellPath(): string {
  return WINDOWS_POWERSHELL;
}

/** An idle or wrong client must not hold the single pipe slot. */
export const HELLO_TIMEOUT_MS = 5_000;

export interface BridgeClient {
  socket: net.Socket;
  /** Data received after the hello line. */
  rest: string;
}

/**
 * Waits for a client that presents `token` as its first line within
 * `helloTimeoutMs` of connecting. Clients with a wrong token, an oversized or a
 * late hello are dropped and the server keeps waiting for the real bridge.
 * The overall deadline is the caller's responsibility (call `dispose`).
 */
export function waitForBridgeClient(
  server: net.Server,
  token: string,
  helloTimeoutMs = HELLO_TIMEOUT_MS,
): { promise: Promise<BridgeClient>; dispose: () => void } {
  let done = false;
  let onConnection: (socket: net.Socket) => void = () => undefined;
  const promise = new Promise<BridgeClient>((resolve) => {
    onConnection = (socket: net.Socket): void => {
      if (done) {
        socket.destroy();
        return;
      }
      let hello = '';
      const deadline = setTimeout(() => socket.destroy(), helloTimeoutMs);
      const drop = (): void => {
        clearTimeout(deadline);
        socket.off('data', onHello);
        socket.destroy();
      };
      const onHello = (chunk: Buffer): void => {
        hello += chunk.toString('utf8');
        const idx = hello.indexOf('\n');
        if (idx === -1) {
          if (hello.length > 256) drop();
          return;
        }
        const line = hello.slice(0, idx).replace(/\r$/, '');
        const got = Buffer.from(line.startsWith('H:') ? line.slice(2) : '', 'utf8');
        const want = Buffer.from(token, 'utf8');
        if (done || got.length !== want.length || !timingSafeEqual(got, want)) {
          drop();
          return;
        }
        clearTimeout(deadline);
        socket.off('data', onHello);
        done = true;
        resolve({ socket, rest: hello.slice(idx + 1) });
      };
      socket.on('data', onHello);
      socket.on('error', () => undefined);
      socket.on('close', () => clearTimeout(deadline));
    };
    server.on('connection', onConnection);
  });
  return {
    promise,
    dispose: () => {
      done = true;
      server.off('connection', onConnection);
    },
  };
}

function psSingleQuote(s: string): string {
  return `'${s.replace(/'/g, "''")}'`;
}

export interface BridgeConfig {
  pipe: string;
  token: string;
  exe: string;
  args: string;
}

/**
 * The bridge script only contains the path and SHA-256 of a config file; the
 * pipe name and token never appear on a command line. The elevated side
 * verifies the hash (so the file cannot be swapped) and deletes the file.
 */
export function buildBridgeScript(configPath: string, configSha256: string): string {
  if (!/^[0-9a-f]{64}$/.test(configSha256)) throw new Error('Invalid config hash');
  return BRIDGE_SCRIPT.replace('__CONFIG_PATH__', Buffer.from(configPath, 'utf8').toString('base64')).replace(
    '__CONFIG_SHA256__',
    configSha256,
  );
}

class Win32BridgeProcess extends BaseVpnProcess {
  private pidValue: number | undefined;
  private buffer = '';

  constructor(
    private readonly socket: net.Socket,
    server: net.Server,
  ) {
    super();
    socket.setEncoding('utf8');
    socket.on('data', (d: string) => this.onData(d));
    socket.on('error', () => undefined);
    socket.on('close', () => {
      if (server.listening) server.close();
      this.emitExit({ code: null, signal: null });
    });
  }

  get pid(): number | undefined {
    return this.pidValue;
  }

  /** Feeds already-received data (the part after the handshake line). */
  feed(data: string): void {
    this.onData(data);
  }

  write(data: string): void {
    if (!this.exited) this.socket.write(`I:${Buffer.from(data, 'utf8').toString('base64')}\n`);
  }

  stop(): Promise<void> {
    if (!this.exited) this.socket.write('S\n');
    return Promise.resolve();
  }

  kill(): Promise<void> {
    if (!this.exited) {
      this.socket.write('K\n');
      // Closing the pipe makes the bridge kill openconnect as well.
      this.socket.end();
    }
    return Promise.resolve();
  }

  private onData(data: string): void {
    this.buffer += data;
    let idx: number;
    while ((idx = this.buffer.indexOf('\n')) !== -1) {
      const line = this.buffer.slice(0, idx).replace(/\r$/, '');
      this.buffer = this.buffer.slice(idx + 1);
      this.onFrame(line);
    }
  }

  private onFrame(line: string): void {
    const type = line.slice(0, 2);
    const payload = line.slice(2);
    switch (type) {
      case 'P:':
        if (/^\d+$/.test(payload)) this.pidValue = Number(payload);
        break;
      case 'O:':
        this.emitOutput('stdout', Buffer.from(payload, 'base64').toString('utf8'));
        break;
      case 'E:':
        this.emitOutput('stderr', Buffer.from(payload, 'base64').toString('utf8'));
        break;
      case 'X:':
        this.emitExit({ code: /^-?\d+$/.test(payload) ? Number(payload) : null, signal: null });
        this.socket.end();
        break;
      default:
        break;
    }
  }
}

/** Windows: openconnect needs administrator rights for the Wintun adapter; elevate via UAC. */
export class Win32ElevatedSpawner implements ProcessSpawner {
  async spawn(req: SpawnRequest): Promise<Win32BridgeProcess> {
    const pipeName = `gp-connect-${randomBytes(16).toString('hex')}`;
    const token = randomBytes(32).toString('hex');
    const pipePath = `\\\\.\\pipe\\${pipeName}`;
    const config: BridgeConfig = {
      pipe: pipeName,
      token,
      exe: req.binary,
      args: req.args.map(quoteWindowsArg).join(' '),
    };
    const configBytes = Buffer.from(JSON.stringify(config), 'utf8');
    // %TEMP% is inside the user profile (user-only ACL); 'wx' refuses existing files.
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'gp-connect-'));
    const configPath = path.join(tmpDir, 'bridge.json');
    await fs.writeFile(configPath, configBytes, { flag: 'wx', mode: 0o600 });
    const cleanup = (): void => {
      void fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
    };
    const script = buildBridgeScript(configPath, createHash('sha256').update(configBytes).digest('hex'));
    const encoded = Buffer.from(script, 'utf16le').toString('base64');
    // -EncodedCommand is not subject to the execution policy; no Bypass needed.
    const innerArgs = ['-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-EncodedCommand', encoded];
    const outer =
      `$ErrorActionPreference = 'Stop'; Start-Process -FilePath ${psSingleQuote(powershellPath())} -Verb RunAs -WindowStyle Hidden ` +
      `-ArgumentList ${innerArgs.map(psSingleQuote).join(',')}`;

    return new Promise<Win32BridgeProcess>((resolve, reject) => {
      let settled = false;
      const server = net.createServer();
      // Enough for a few stray clients without letting anyone exhaust resources.
      server.maxConnections = 16;
      const waiter = waitForBridgeClient(server, token);
      const fail = (err: SpawnError): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        waiter.dispose();
        server.close();
        cleanup();
        reject(err);
      };
      const timer = setTimeout(
        () => fail(new SpawnError('PRIVILEGES_DENIED', 'Timed out waiting for the elevated openconnect helper')),
        CONNECT_TIMEOUT_MS,
      );
      void waiter.promise.then(({ socket, rest }) => {
        if (settled) {
          socket.destroy();
          return;
        }
        settled = true;
        clearTimeout(timer);
        waiter.dispose();
        // Stop accepting: the authenticated bridge keeps its socket; anything
        // that still manages to connect is dropped immediately.
        server.on('connection', (late: net.Socket) => late.destroy());
        server.close();
        cleanup();
        const proc = new Win32BridgeProcess(socket, server);
        proc.feed(rest);
        resolve(proc);
      });
      server.on('error', (err) => fail(new SpawnError('UNKNOWN', `Named pipe error: ${err.message}`, { cause: err })));

      server.listen(pipePath, () => {
        execFile(
          powershellPath(),
          ['-NoProfile', '-NonInteractive', '-Command', outer],
          { windowsHide: true, timeout: CONNECT_TIMEOUT_MS, env: { ...process.env, PSModulePath: SYSTEM_PS_MODULES } },
          (err, _stdout, stderr) => {
            if (!err) return;
            const text = String(stderr);
            fail(
              new SpawnError(
                /cancel/i.test(text) ? 'PRIVILEGES_DENIED' : 'UNKNOWN',
                `Could not start openconnect with administrator rights: ${text.trim() || err.message}`,
              ),
            );
          },
        );
      });
    });
  }
}
