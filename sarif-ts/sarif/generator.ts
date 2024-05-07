

import { Location, Run, Result, SarifDocument, SarifError } from "./types.js";
import { sarifSchemeVersion } from "./template.js";
import { makeSourceLocation, makeBinaryLocation } from "./utils.js";

export class SarifGenerator {
    private run: Run = { tool: { driver: { name: "", version: "", rules: [] } }, results: [] };
    public results: Result[] = [];
    private runs: Run[] = [];

    constructor() {

    }

    appendRun(toolName: string, toolVersion: string) {
        this.runs.push({
            tool: {
                driver: {
                    name: toolName,
                    version: toolVersion,
                    rules: []
                }
            },
            results: this.results
        })
        this.results = [];
    }

    addError(message: string, location: Location) {
        this.results.push({ level: "error", message, location });
    }

    addWarning(message: string, location: Location) {
        this.results.push({ level: "warning", message, location });
    }

    addNote(message: string, location: Location) {
        this.results.push({ level: "note", message, location });
    }

    getSarif(): SarifDocument | SarifError {
        if (this.run.results.length === 0) {
            return new SarifError("SARIF document missing results");
        }
        return { version: sarifSchemeVersion, runs: this.runs };
    }
}

