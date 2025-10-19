using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace TrafficAnalysisAPI.Migrations
{
    /// <inheritdoc />
    public partial class AddTestData : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "TrafficSessions",
                columns: new[] { "Id", "Description", "EndTime", "SessionName", "StartTime" },
                values: new object[] { 1, "Тестовая сессия для демонстрации", null, "Test Session 2025-01-12", new DateTime(2025, 10, 19, 12, 0, 0, 0, DateTimeKind.Utc) });

            migrationBuilder.InsertData(
                table: "NetworkPackets",
                columns: new[] { "Id", "DestinationIP", "PacketSize", "Port", "Protocol", "SessionId", "SourceIP", "Timestamp" },
                values: new object[,]
                {
                    { 1, "10.0.0.1", 500, 80, "TCP", 1, "192.168.1.1", new DateTime(2025, 10, 19, 12, 5, 0, 0, DateTimeKind.Utc) },
                    { 2, "10.0.0.2", 2000, 23, "TCP", 1, "45.142.120.15", new DateTime(2025, 10, 19, 12, 10, 0, 0, DateTimeKind.Utc) },
                    { 3, "10.0.0.3", 1800, 445, "TCP", 1, "45.142.120.15", new DateTime(2025, 10, 19, 12, 15, 0, 0, DateTimeKind.Utc) },
                    { 4, "10.0.0.4", 1600, 3389, "TCP", 1, "192.168.1.2", new DateTime(2025, 10, 19, 12, 20, 0, 0, DateTimeKind.Utc) },
                    { 5, "10.0.0.5", 600, 443, "HTTPS", 1, "45.142.120.15", new DateTime(2025, 10, 19, 12, 25, 0, 0, DateTimeKind.Utc) }
                });

            migrationBuilder.InsertData(
                table: "TrafficAnalyses",
                columns: new[] { "Id", "Description", "DetectedAt", "IsMalicious", "MLModelScore", "PacketId", "ThreatLevel" },
                values: new object[,]
                {
                    { 1, null, new DateTime(2025, 10, 19, 12, 10, 0, 0, DateTimeKind.Utc), true, 0.69999999999999996, 2, "High" },
                    { 2, null, new DateTime(2025, 10, 19, 12, 15, 0, 0, DateTimeKind.Utc), true, 0.84999999999999998, 3, "Critical" },
                    { 3, null, new DateTime(2025, 10, 19, 12, 20, 0, 0, DateTimeKind.Utc), false, 0.5, 4, "Medium" },
                    { 4, null, new DateTime(2025, 10, 19, 12, 25, 0, 0, DateTimeKind.Utc), false, 0.29999999999999999, 5, "Low" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "NetworkPackets",
                keyColumn: "Id",
                keyValue: 1);

            migrationBuilder.DeleteData(
                table: "TrafficAnalyses",
                keyColumn: "Id",
                keyValue: 1);

            migrationBuilder.DeleteData(
                table: "TrafficAnalyses",
                keyColumn: "Id",
                keyValue: 2);

            migrationBuilder.DeleteData(
                table: "TrafficAnalyses",
                keyColumn: "Id",
                keyValue: 3);

            migrationBuilder.DeleteData(
                table: "TrafficAnalyses",
                keyColumn: "Id",
                keyValue: 4);

            migrationBuilder.DeleteData(
                table: "NetworkPackets",
                keyColumn: "Id",
                keyValue: 2);

            migrationBuilder.DeleteData(
                table: "NetworkPackets",
                keyColumn: "Id",
                keyValue: 3);

            migrationBuilder.DeleteData(
                table: "NetworkPackets",
                keyColumn: "Id",
                keyValue: 4);

            migrationBuilder.DeleteData(
                table: "NetworkPackets",
                keyColumn: "Id",
                keyValue: 5);

            migrationBuilder.DeleteData(
                table: "TrafficSessions",
                keyColumn: "Id",
                keyValue: 1);
        }
    }
}
