namespace TrafficAnalysisAPI.Utils
{
    public static class Constants
    {

        public static readonly HashSet<int> SuspiciousPorts = new()
        {
            23,    // Telnet
            135,   // RPC
            139,   // NetBIOS
            445,   // SMB
            3389,  // RDP
            5900   // VNC
        };

        public static readonly HashSet<string> StandardProtocols = new()
        {
            "ARP",
            "DNS",
            "ICMP",
            "HTTP",
            "HTTPS",
            "TCP",
            "TLS",
            "UDP"
        };

        public const int MaxPacketSize = 65535;
        public const int StandardPacketSize = 1500;
        public const double ThreatScoreThreshold = 50.0;

        // Пороги для классификации угроз
        public const double CriticalThreshold = 0.8;
        public const double HighThreshold = 0.6;
        public const double MediumThreshold = 0.4;
    }
}