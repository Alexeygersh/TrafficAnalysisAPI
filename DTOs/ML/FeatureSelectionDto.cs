namespace TrafficAnalysisAPI.DTOs.ML
{
    /// <summary>Рейтинг одного признака.</summary>
    public class FeatureRankDto
    {
        public string Feature { get; set; } = "";
        public double? Silhouette { get; set; }  // null если константа / не считается
        public int Rank { get; set; }
        public string Note { get; set; } = "";
    }

    /// <summary>Полный ответ endpoint'а feature-selection.</summary>
    public class FeatureSelectionResultDto
    {
        public int TotalSamples { get; set; }
        public int TotalFeatures { get; set; }
        public int ValidFeatures { get; set; }
        public List<FeatureRankDto> Ranking { get; set; } = new();
        public List<string> Top10 { get; set; } = new();
        public string? Chart { get; set; }       // data:image/png;base64,...
        public string? Error { get; set; }       // если что-то не так
    }
}
