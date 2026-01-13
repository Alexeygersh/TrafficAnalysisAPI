using TrafficAnalysisAPI.DTOs;

namespace TrafficAnalysisAPI.Services.Interfaces
{
    public interface IPythonMLService
    {
        // Парсинг CSV
        List<ParsedPacketDto> ParseWiresharkCsv(string csvContent);

        // Расчёт метрик
        List<SourceMetricsDto> CalculateSourceMetrics(List<ParsedPacketDto> packets);

        // Кластеризация
        List<SourceClusterResultDto> ClusterSources(
            List<SourceMetricsDto> sources,
            string method = "kmeans",
            int nClusters = 3
        );

        // Threat scoring
        PacketThreatResultDto CalculatePacketThreatScore(object packetData);

        // Массовый scoring
        Dictionary<int, PacketThreatResultDto> BatchScorePackets(
            List<object> packets
        );


        VisualizationResultDto VisualizeCluster(object clusterData);
        VisualizationResultDto CreateClusterHeatmap(object clusterData);
        VisualizationResultDto CreateDangerTimeline(object clusterData);
    }
}