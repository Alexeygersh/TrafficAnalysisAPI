using TrafficAnalysisAPI.DTOs;
using TrafficAnalysisAPI.DTOs.ML;

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

        // Threat scoring (пакетный уровень)
        PacketThreatResultDto CalculatePacketThreatScore(object packetData);
        Dictionary<int, PacketThreatResultDto> BatchScorePackets(List<object> packets);

        // Визуализации
        VisualizationResultDto VisualizeCluster(object clusterData);
        VisualizationResultDto CreateClusterHeatmap(object clusterData);
        VisualizationResultDto CreateDangerTimeline(object clusterData);

        // ---------------------------------------------------------------
        // Гибридная IDS (source-level анализ)
        // ---------------------------------------------------------------

        /// <summary>
        /// ML-предсказание для списка источников трафика (source-level).
        /// Использует HybridIDS: Random Forest + Isolation Forest.
        /// </summary>
        /// <param name="sources">Список метрик источников из SourceMetrics</param>
        /// <returns>Список предсказаний — по одному на каждый IP-источник</returns>
        List<SourceMLPredictionDto> PredictSourcesBatch(List<SourceMetricsDto> sources);


        /// <summary>
        /// Строит flow-признаки из списка сырых пакетов (извлечённых из .pcap).
        /// Вызывает Python-модуль flow_features.py.
        /// </summary>
        List<FlowFeaturesDto> BuildFlowsFromPackets(
            List<TrafficAnalysisAPI.Services.Implementations.RawPacket> packets);


        /// <summary>
        /// ML-предсказание для списка flow.
        /// modelType: "rf" (RandomForest+IF, hybrid_ids_v2.pkl) или
        ///            "catboost" (CatBoost+IF, catboost_ids_v2.pkl).
        /// </summary>
        List<FlowMLPredictionDto> PredictFlowsBatch(
            List<TrafficAnalysisAPI.Models.FlowMetrics> flows,
            string modelType = "rf");

    }
}
