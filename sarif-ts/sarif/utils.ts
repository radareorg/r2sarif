import { SourceLineLocation, SourceLocation, BinaryLocation } from "./types";

import { Ajv , ValidateFunction } from "ajv";

const sarifSchema = require("../Sarif2.schema.json");
const JSONSchemaDraft4Definition = require('../json-schema-draft-04.json');

export class SarifVerifier {
    private validateCallback: ValidateFunction;

    constructor() {
        const verifier = new Ajv()
        verifier.addMetaSchema(JSONSchemaDraft4Definition);
        this.validateCallback = verifier.compile(sarifSchema);
    }
    validate(sarif: any) : boolean {
        return this.validateCallback(sarif);
    }
}

export function verifySarif(sarif: any): boolean {
    const sv = new SarifVerifier();
    return sv.validate(sarif);
}

export function makeSourceLocation(fileUri: string, lineNumber: number, columnNumber?: number): SourceLineLocation | SourceLocation {
    if (columnNumber === undefined) {
        return {
            fileUri,
            lineNumber,
        };
    }
    return {
        fileUri,
        lineNumber,
        columnNumber
    };
}

export function makeBinaryLocation(fileUri: string, memoryAddress: string, offset: number, length: number): BinaryLocation {
    return {
        physicalLocation: {
            artifactLocation: {
                uri: "binary://" + fileUri,
                uriBaseId: "%SRCROOT%"
            },
            region: {
                startByteOffset: offset,
                byteLength: length
            }
        },
        properties: {
            memoryAddress
        }
    };
}