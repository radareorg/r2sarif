import { Location, Run, Rule, Result, ResultLevel, SarifDocument, SarifError, Driver } from "./types.js";
import { sarifSchemeVersion, sarifTemplate } from "./template.js";
// import { makeSourceLocation, makeBinaryLocation } from "./utilsgen.js";

export class SarifRun {
    toolName: string;
    toolVersion?: string;
    toolSemanticVersion?: string;

    constructor(toolName: string, toolVersion?: string, toolSemanticVersion?: string) {
        this.toolName = toolName;
    }
    toString(): string {
        return "run";
    }
    asRun(): Run {
        return { tool: { driver: { name: this.toolName, semanticVersion: "", version: "", rules: [] } }, results: [] };
    }
}

function newResult(level: ResultLevel, ruleId: string, message: string, location: Location): Result {
    return { level: level, kind: "pass", ruleId: ruleId, "message": { text: message }, locations: [location] };
}

export class SarifGenerator {
    private doc: SarifDocument;
    private currentDriver: Driver | null = null;

    constructor() {
        this.doc = sarifTemplate;
    }

    appendRun() : Error | null {
        if (this.currentDriver === null) {
            return new SarifError("No driver selected");
        }
        const newRun: Run = {
            tool: {
                driver: {
                    name: this.currentDriver.name,
                    semanticVersion: this.currentDriver.semanticVersion,
                    version: this.currentDriver.version,
                    rules: []
                }
            },
            results: []
        }
        this.doc.runs.push(newRun);
        return null;
    }

    selectDriver(driver: Driver) {
        this.currentDriver = driver;
    }

    addResult(result: Result) {
        if (this.currentDriver === null) {
            r2.error("No driver selected, so we can't add a result");
            return;
        }
        if (this.doc.runs.length == 0) {
            this.appendRun();
        }
        const lastRun = this.doc.runs[this.doc.runs.length-1];
        const ruleId = result.ruleId;
        let validRule : Rule | null = null;
        for (const rule of this.currentDriver.rules) {
            if (rule.id === ruleId) {
                validRule = rule;
                break;
            }
        }
        if (validRule === null) {
            r2.error("Invalid ruleId");
            return;
        }
        let registeredRule = false;
        for (const rule of lastRun.tool.driver.rules) {
            if (rule.id === validRule.id) {
                registeredRule = true;
                break;
            }
        }
        if (!registeredRule) {
            lastRun.tool.driver.rules.push(validRule);
        }
        // if last run was made with the same driver no need to add it again
        // this.doc.runs[this.runs.length-1].results.push(result);
        if (lastRun && lastRun.results) {
            lastRun.results.push(result);
        } else {
            r2.error("No run to add error");
        }
    }

    addError(ruleId: string, message: string, location: Location) {
        this.addResult(newResult("error", ruleId, message, location));
    }
    addWarning(ruleId: string, message: string, location: Location) {
        this.addResult(newResult("warning", ruleId, message, location));
    }
    addNote(ruleId: string, message: string, location: Location) {
        this.addResult(newResult("note", ruleId, message, location));
    }

    getSarif(): SarifDocument | SarifError {
        if (!this.doc || this.doc.runs.length === 0) {
            return new SarifError("This SARIF document have no results");
        }
        return this.doc;
    }
}

