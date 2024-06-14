// ajv is written in commonjs, so it requires

import { SourceLineLocation, SourceLocation, BinaryLocation } from "./types";

import { readFileSync } from "fs";
import { Ajv2020, ErrorObject, ValidateFunction } from "ajv/dist/2020"
import ajv from "ajv"
import addFormats from "ajv-formats";

// move those files into the `assets/` directory
// const sarifSchemaJson = "sarif-schema-2.1.0.json";
const sarifSchema210 = "sarif-schema-2.1.0.json";
const sarifSchema220 = "sarif-schema-2.2.0.json";

export class SarifVerifier {
    private validateDocument: ValidateFunction;
    private draft06validator() : ValidateFunction{
        const verifier = new ajv();
        addFormats(verifier);
        const draft6MetaSchema = require("ajv/dist/refs/json-schema-draft-06.json")
        verifier.addMetaSchema(draft6MetaSchema)
        const sarifSchema = JSON.parse(readFileSync(sarifSchema210, "utf-8"));
        this.validateDocument = verifier.compile(sarifSchema);
        return verifier.compile(sarifSchema);
    }
    private v2020validator() : ValidateFunction{
        // seems like the latest **official** standard is 2.1, 2.2 have some issues
        const verifier = new Ajv2020({validateSchema: false});
        addFormats(verifier);
        const sarifSchema = JSON.parse(readFileSync(sarifSchema220, "utf-8"));
        return verifier.compile(sarifSchema);
    }
    constructor() {
        this.validateDocument= this.draft06validator();
        // this.validateDocument= this.v2020validator();
    }
    validate(sarif: any) : true | Array<ErrorObject>{
        const result = this.validateDocument(sarif)
        if (result === true) {
            return true;
        }
        return this.validateDocument.errors as Array<ErrorObject>;
    }
}


export function verifySarif(sarif: any): true | Array<ErrorObject> {
    const sv = new SarifVerifier();
    return sv.validate(sarif);
}
