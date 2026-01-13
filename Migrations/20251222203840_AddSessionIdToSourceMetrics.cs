using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace TrafficAnalysisAPI.Migrations
{
    /// <inheritdoc />
    public partial class AddSessionIdToSourceMetrics : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "Protocols",
                table: "SourceMetrics",
                type: "character varying(500)",
                maxLength: 500,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "character varying(200)",
                oldMaxLength: 200,
                oldNullable: true);

            migrationBuilder.AddColumn<int>(
                name: "SessionId",
                table: "SourceMetrics",
                type: "integer",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_SourceMetrics_SessionId",
                table: "SourceMetrics",
                column: "SessionId");

            migrationBuilder.AddForeignKey(
                name: "FK_SourceMetrics_TrafficSessions_SessionId",
                table: "SourceMetrics",
                column: "SessionId",
                principalTable: "TrafficSessions",
                principalColumn: "Id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_SourceMetrics_TrafficSessions_SessionId",
                table: "SourceMetrics");

            migrationBuilder.DropIndex(
                name: "IX_SourceMetrics_SessionId",
                table: "SourceMetrics");

            migrationBuilder.DropColumn(
                name: "SessionId",
                table: "SourceMetrics");

            migrationBuilder.AlterColumn<string>(
                name: "Protocols",
                table: "SourceMetrics",
                type: "character varying(200)",
                maxLength: 200,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "character varying(500)",
                oldMaxLength: 500,
                oldNullable: true);
        }
    }
}
