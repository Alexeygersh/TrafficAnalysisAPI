using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace TrafficAnalysisAPI.Migrations
{
    /// <inheritdoc />
    public partial class NewCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "SourceMetrics",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    SourceIP = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: false),
                    PacketCount = table.Column<int>(type: "integer", nullable: false),
                    PacketsPerSecond = table.Column<double>(type: "double precision", nullable: false),
                    AveragePacketSize = table.Column<double>(type: "double precision", nullable: false),
                    TotalBytes = table.Column<long>(type: "bigint", nullable: false),
                    Duration = table.Column<double>(type: "double precision", nullable: false),
                    ClusterId = table.Column<int>(type: "integer", nullable: false),
                    IsDangerous = table.Column<bool>(type: "boolean", nullable: false),
                    DangerScore = table.Column<double>(type: "double precision", nullable: false),
                    ClusterName = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    UniquePorts = table.Column<int>(type: "integer", nullable: false),
                    Protocols = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    CalculatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SourceMetrics", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SourceMetrics_ClusterId",
                table: "SourceMetrics",
                column: "ClusterId");

            migrationBuilder.CreateIndex(
                name: "IX_SourceMetrics_IsDangerous",
                table: "SourceMetrics",
                column: "IsDangerous");

            migrationBuilder.CreateIndex(
                name: "IX_SourceMetrics_SourceIP",
                table: "SourceMetrics",
                column: "SourceIP");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SourceMetrics");
        }
    }
}
