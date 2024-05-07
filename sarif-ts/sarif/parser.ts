import { SarifDocument, Result, Location } from "./types.js"; // Assuming sarif-types.ts defines the interfaces

export class SarifParser {
    public parse(sarifString: string): SarifDocument | Error | undefined {
        try {
            const sarifDoc: SarifDocument = JSON.parse(sarifString);
            return this.validateSarif(sarifDoc); // Add validation (optional)
        } catch (err) {
            return err;
        }
    }

    private validateSarif(sarifDoc: SarifDocument): Error | undefined {
        if (!sarifDoc.version || !sarifDoc.runs) {
            return new Error("SARIF document missing required properties (version or runs)");
        }

        // Validate runs and results structure (basic)
        sarifDoc.runs.forEach((run) => {
            if (!run.tool || !run.tool.driver || !run.tool.driver.name || !run.tool.driver.version) {
                return new Error("SARIF run missing required tool information");
            }

            run.results.forEach((result) => {
                if (!result.level || !result.message) {
                    return new Error("SARIF result missing required level or message");
                }
                // You can add more specific checks for location format (optional)
            });
        });
    }
}