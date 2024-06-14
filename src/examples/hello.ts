import { SarifGenerator } from "../sarif/generator.js";
import { makeSourceLocation, makeBinaryLocation } from "../sarif/utils.js";

// Usage Example
const sg = new SarifGenerator();
const sarifRun = sg.appendRun("MyLinter", "1.0.0");
sarifRun.addRules();
sarifRun.addErrorForRule();
sg.addError("Missing semicolon", { fileUri: "main.js", lineNumber: 10, columnNumber: 5 });
sg.addWarning("Potential code smell", { fileUri: "utils.ts", lineNumber: 25 });
sg.addNote("More tests are needed here", makeSourceLocation("tests.js", 10, 5));
sg.addError("Deprecated API call", makeBinaryLocation("MainApp", "0x12345678", 0x4546, 4));

const sarifDoc = sg.getSarif();
if (sarifDoc instanceof Error) {
    console.log(sarifDoc.message);
} else {
    // Pretty-printed SARIF document
    console.log(JSON.stringify(sarifDoc, null, 2));
}