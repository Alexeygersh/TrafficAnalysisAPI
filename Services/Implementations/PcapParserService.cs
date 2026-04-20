using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace TrafficAnalysisAPI.Services.Implementations
{
    /// <summary>
    /// Один пакет, извлечённый из .pcap файла.
    /// Содержит все поля, необходимые для построения flow-метрик на стороне Python.
    ///
    /// Важно: поля в PascalCase — System.Text.Json по умолчанию сериализует их
    /// в camelCase при отправке в Python, а на стороне Python мы уже умеем читать
    /// и то и другое через _get_field().
    /// </summary>
    public class RawPacket
    {
        public double TimestampSec { get; set; }   // Unix timestamp в секундах (double для микросекунд)
        public string SourceIP { get; set; } = "";
        public string DestinationIP { get; set; } = "";
        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }
        public string Protocol { get; set; } = ""; // TCP / UDP / ICMP / OTHER
        public int PacketSize { get; set; }        // длина пакета в байтах (IP layer)
        public int HeaderLength { get; set; }      // длина заголовков (IP + TCP/UDP)

        // TCP-флаги (0 если не TCP)
        public bool FlagFIN { get; set; }
        public bool FlagSYN { get; set; }
        public bool FlagRST { get; set; }
        public bool FlagPSH { get; set; }
        public bool FlagACK { get; set; }
        public bool FlagURG { get; set; }
        public bool FlagECE { get; set; }
        public bool FlagCWR { get; set; }

        // TCP window (0 если не TCP)
        public int WindowSize { get; set; }

        // Payload size (PacketSize - HeaderLength)
        public int PayloadSize { get; set; }
    }

    public interface IPcapParserService
    {
        /// <summary>
        /// Читает .pcap файл и возвращает список пакетов с извлечёнными полями.
        /// TCP/UDP парсится полностью, остальные протоколы с базовыми полями.
        /// </summary>
        List<RawPacket> ParsePcapFile(string filePath);
    }

    public class PcapParserService : IPcapParserService
    {
        private readonly ILogger<PcapParserService> _logger;

        public PcapParserService(ILogger<PcapParserService> logger)
        {
            _logger = logger;
        }

        public List<RawPacket> ParsePcapFile(string filePath)
        {
            var result = new List<RawPacket>();

            if (!File.Exists(filePath))
                throw new FileNotFoundException($"PCAP file not found: {filePath}");

            _logger.LogInformation($"[PcapParser] Opening file: {filePath}");

            // Открываем файл через CaptureFileReaderDevice (offline-режим, Npcap не нужен для чтения)
            using var device = new CaptureFileReaderDevice(filePath);
            device.Open();

            int totalRead = 0;
            int skipped = 0;

            PacketCapture e;
            GetPacketStatus status;
            while ((status = device.GetNextPacket(out e)) == GetPacketStatus.PacketRead)
            {
                totalRead++;
                try
                {
                    var raw = ExtractPacket(e);
                    if (raw != null)
                        result.Add(raw);
                    else
                        skipped++;
                }
                catch (Exception ex)
                {
                    // Не роняем весь импорт из-за одного битого пакета — логируем и идём дальше
                    _logger.LogWarning($"[PcapParser] Skipped malformed packet #{totalRead}: {ex.Message}");
                    skipped++;
                }
            }

            device.Close();

            _logger.LogInformation(
                $"[PcapParser] Done. Total={totalRead}, Parsed={result.Count}, Skipped={skipped}");

            return result;
        }

        /// <summary>
        /// Извлекает нужные поля из одного пакета. Возвращает null если пакет
        /// не IP (ARP, STP и т.д.) — такие нам не интересны для flow-анализа.
        /// </summary>
        private RawPacket? ExtractPacket(PacketCapture capture)
        {
            var rawData = capture.Data;
            var linkLayerType = capture.GetPacket().LinkLayerType;
            var packet = Packet.ParsePacket(linkLayerType, rawData.ToArray());

            // Ищем IP-слой (IPv4 или IPv6)
            var ipPacket = packet.Extract<IPPacket>();
            if (ipPacket == null)
                return null; // не IP — пропускаем

            var result = new RawPacket
            {
                TimestampSec = capture.Header.Timeval.Seconds + capture.Header.Timeval.MicroSeconds / 1_000_000.0,
                SourceIP = ipPacket.SourceAddress.ToString(),
                DestinationIP = ipPacket.DestinationAddress.ToString(),
                PacketSize = ipPacket.TotalLength > 0 ? ipPacket.TotalLength : rawData.Length,
            };

            // TCP
            var tcp = packet.Extract<TcpPacket>();
            if (tcp != null)
            {
                result.Protocol = "TCP";
                result.SourcePort = tcp.SourcePort;
                result.DestinationPort = tcp.DestinationPort;
                result.HeaderLength = (ipPacket.HeaderLength * 4) + (tcp.DataOffset * 4);
                result.PayloadSize = Math.Max(0, result.PacketSize - result.HeaderLength);

                result.FlagFIN = tcp.Finished;
                result.FlagSYN = tcp.Synchronize;
                result.FlagRST = tcp.Reset;
                result.FlagPSH = tcp.Push;
                result.FlagACK = tcp.Acknowledgment;
                result.FlagURG = tcp.Urgent;
                result.FlagECE = tcp.ExplicitCongestionNotificationEcho;
                result.FlagCWR = tcp.CongestionWindowReduced;

                result.WindowSize = tcp.WindowSize;
                return result;
            }

            // UDP
            var udp = packet.Extract<UdpPacket>();
            if (udp != null)
            {
                result.Protocol = "UDP";
                result.SourcePort = udp.SourcePort;
                result.DestinationPort = udp.DestinationPort;
                result.HeaderLength = (ipPacket.HeaderLength * 4) + 8; // UDP header всегда 8 байт
                result.PayloadSize = Math.Max(0, result.PacketSize - result.HeaderLength);
                return result;
            }

            // ICMP
            var icmpV4 = packet.Extract<IcmpV4Packet>();
            if (icmpV4 != null)
            {
                result.Protocol = "ICMP";
                result.HeaderLength = ipPacket.HeaderLength * 4 + 8;
                result.PayloadSize = Math.Max(0, result.PacketSize - result.HeaderLength);
                return result;
            }

            var icmpV6 = packet.Extract<IcmpV6Packet>();
            if (icmpV6 != null)
            {
                result.Protocol = "ICMPv6";
                result.HeaderLength = ipPacket.HeaderLength * 4 + 8;
                result.PayloadSize = Math.Max(0, result.PacketSize - result.HeaderLength);
                return result;
            }

            // Остальные IP-протоколы (GRE, IPSec и т.д.) — сохраняем с номером
            result.Protocol = $"IP_PROTO_{(int)ipPacket.Protocol}";
            result.HeaderLength = ipPacket.HeaderLength * 4;
            result.PayloadSize = Math.Max(0, result.PacketSize - result.HeaderLength);
            return result;
        }
    }
}
