namespace TrafficAnalysisAPI.DTOs.ML
{
    /// <summary>
    /// Результат ML-предсказания для одного flow (5-tuple).
    /// Возвращается из POST /api/ml/flow-analyze.
    /// </summary>
    public class FlowMLPredictionDto
    {
        public int FlowId { get; set; }
        public string SourceIP { get; set; } = "";
        public string DestinationIP { get; set; } = "";
        public int DestinationPort { get; set; }
        public string Protocol { get; set; } = "";

        /// <summary>Классифицирован ли flow как атака (RF или IF или оба)</summary>
        public bool IsAttack { get; set; }

        /// <summary>Уверенность Random Forest (0-1) — вероятность класса "атака"</summary>
        public double Confidence { get; set; }

        /// <summary>Low / Medium / High / Critical</summary>
        public string ThreatLevel { get; set; } = "Low";

        /// <summary>supervised / unsupervised / both / none</summary>
        public string Method { get; set; } = "none";

        /// <summary>0 = норма, 1 = атака (только RF)</summary>
        public int RfPrediction { get; set; }

        /// <summary>true если Isolation Forest считает flow аномалией</summary>
        public bool IsAnomaly { get; set; }
    }

    /// <summary>Сводный результат ML-анализа сессии на уровне flow.</summary>
    public class FlowMLAnalyzeResultDto
    {
        public int SessionId { get; set; }
        public int TotalFlows { get; set; }
        public int AttackFlows { get; set; }
        public int AnomalyFlows { get; set; }
        public Dictionary<string, int> ThreatLevelBreakdown { get; set; } = new();
        public Dictionary<string, int> MethodBreakdown { get; set; } = new();
        public List<string> UsedFeatures { get; set; } = new();
        public long ElapsedMs { get; set; }
        public List<FlowMLPredictionDto> Predictions { get; set; } = new();
    }

    /// <summary>Meta из global_features.json — то на чём обучалась модель.</summary>
    public class ModelMetaDto
    {
        public List<string> FeatureNames { get; set; } = new();
        public string ModelVersion { get; set; } = "";
        public string ModelFile { get; set; } = "";
        public string TrainedOn { get; set; } = "";
        public Dictionary<string, List<string>>? FeaturesByBlock { get; set; }
        public string? SelectionMethod { get; set; }
    }
}
