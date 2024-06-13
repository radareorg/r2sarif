import { SarifDocument, Result, Location } from "./types.js"; // Assuming sarif-types.ts defines the interfaces

export class SarifParser {
    public parse(sarifString: string): SarifDocument | Error {
        const obj: any = JSON.parse(sarifString);
        if (typeof obj["driver"] === "object") {
            return this.parseDriver(sarifString);
        }
        return this.parseDocument(sarifString)
    }

    public parseDocument(sarifString: string): SarifDocument | Error {
        try {
            const sarifDoc: SarifDocument = JSON.parse(sarifString);
            const res = this.validateSarif(sarifDoc); // Add validation (optional)
            if (res instanceof Error) {
                return res;
            }
            return sarifDoc;
        } catch (err) {
            return err;
        }
    }

    public parseDriver(sarifString: string) : SarifDocument | Error {
        return new Error("Not implemented");
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