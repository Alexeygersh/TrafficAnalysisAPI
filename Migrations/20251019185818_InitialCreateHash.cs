using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace TrafficAnalysisAPI.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreateHash : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "Users",
                keyColumn: "Id",
                keyValue: 1,
                column: "PasswordHash",
                value: "$2a$12$C83vSlJeLDe9HQKCTtAZauTtlT2s8sVbZtZIvGAmlrAR14wDDRkE.");

            migrationBuilder.UpdateData(
                table: "Users",
                keyColumn: "Id",
                keyValue: 2,
                column: "PasswordHash",
                value: "$2a$12$uMJ6PYfgWhWPNFTshq.o1uukT0yYAuju3J6mVv1M32MXtrFhpnYB2");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "Users",
                keyColumn: "Id",
                keyValue: 1,
                column: "PasswordHash",
                value: "$2a$11$Zx8H1qGKp5L2rN8dK7vZx.YQ3L5mB9Kp2fH7nJ4xR6tW8yV3cA1Bm");

            migrationBuilder.UpdateData(
                table: "Users",
                keyColumn: "Id",
                keyValue: 2,
                column: "PasswordHash",
                value: "$2a$11$xB5yL8Np2K6fR9tM3vJ7c.WQ2L4mA8Jp1eG6mI3wP5rU7xT2bZ0Am");
        }
    }
}
