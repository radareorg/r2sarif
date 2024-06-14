import { Location, Run, Result, SarifDocument, SarifError } from "./types.js";
import { sarifSchemeVersion } from "./template.js";
// import { makeSourceLocation, makeBinaryLocation } from "./utilsgen.js";

export class SarifRun {
    constructor(toolName: string, toolVersion: string) {

    }
    toString(): string {
        return "run";
    }
}

export class SarifGenerator {
    private run: Run = { tool: { driver: { name: "", semanticVersion: "", version: "", rules: [] } }, results: [] };
    public results: Result[] = [];
    private runs: SarifRun[] = [];

    constructor() {

    }

    appendRun(toolName: string, toolVersion: string) : SarifRun {
        const sr = new SarifRun(toolName, toolVersion);
        this.runs.push(sr);
        return sr;
        /*
        this.runs.push({
            tool: {
                driver: {
                    name: toolName,
                    version: toolVersion,
                    semanticVersion: toolVersion,
                    rules: []
                }
            },
            results: this.results
        })
        this.results = []; 
        */
    }

    addError(ruleId: string, message: string, location: Location) {
        this.results.push({ level: "error", ruleId: ruleId, "message": {text: message}, locations: [location] });
    }

    addWarning(ruleId: string, message: string, location: Location) {
        this.results.push({ ruleId: ruleId, level: "warning","message": {text:message}, locations: [location] });
    }

    addNote(ruleId: string, message: string, location: Location) {
        this.results.push({ ruleId: ruleId, level: "note", "message": {text:message}, locations: [location ]});
    }

    getSarif(): SarifDocument | SarifError {
        if (this.run.results && this.run.results.length === 0) {
            return new SarifError("SARIF document missing results");
        }
        return { version: sarifSchemeVersion, runs: []};
    }
}

