namespace TrafficAnalysisAPI.DTOs
{
    public class VisualizationResultDto
    {
        public string? Image { get; set; } // Base64 image
        public List<double>? ExplainedVariance { get; set; }
        public double? TotalVarianceExplained { get; set; }
        public string? Error { get; set; }
    }
}