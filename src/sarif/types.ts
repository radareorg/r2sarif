// Simplified SARIF Document Structure

export interface ResultMessage {
    text: string;
    arguments?: string[];
}

export interface StringMap {
    [key: string]: string;
}
export interface Result {
    ruleId: string;
    level: ResultLevel;
    kind?: string;
    message: ResultMessage;
    locations: Location[]; // (optional) file, line, column information
    codeFlows?: CodeFlow[]; // (optional)
    relatedLocations?: Location[]; // (optional) additional locations
    properties?: any;
}

// it's ugly that typescript can't enforce this at the language level
const levels = ["error", "warning", "note"];
export type ResultLevel = (typeof levels)[number];
export function isValidLevel(k: string) : boolean {
    return levels.indexOf(k) !== -1;
}

const kinds = [ "notApplicable", "pass", "fail", "review", "open", "informational" ];
export type ResultKind = (typeof kinds)[number];
export function isValidKind(k: string) : boolean {
    return kinds.indexOf(k) !== -1;
}

export interface SourceLocation {
    fileUri: string;
    lineNumber: number;
    columnNumber: number;
}

export class SarifError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "SarifError"; // this.constructor.name;
    }
}

export interface BinaryLocation {
    message?: string;
    physicalLocation: BinaryPhysicalLocation;
    properties: BinaryLocationProperties;
}

export type Location = SourceLocation | BinaryLocation | SourceLineLocation;

export interface ThreadFlowMessage {
  text: string;
}
export interface ThreadFlowLocation {
  module: string;
  message: ThreadFlowMessage;
  location: BinaryLocation;
  // physicalLocation: BinaryPhysicalLocation;
  // properties: any; // memoryAddress: string
}

export interface ThreadFlow {
  id: string;
  message: ThreadFlowMessage;
  locations: ThreadFlowLocation[];
}

export interface CodeFlow {
    threadFlows: ThreadFlow[]
}

export interface BinaryLocationProperties {
    memoryAddress: string;
}

export type SourceLineLocation = Partial<
    Pick<SourceLocation, 'fileUri'> &
    Pick<SourceLocation, 'lineNumber'> &
    { columnNumber: 0 }>;

export interface BinaryArtifactLocation {
    uri: string; // "binary://example-binary",
    uriBaseId?: string; // "%SRCROOT%"
}

export interface BinaryPhysicalLocationAddress {
    absoluteAddress: number;
}

export interface BinaryPhysicalLocation {
    artifactLocation: BinaryArtifactLocation;
    address?: BinaryPhysicalLocationAddress;
    region: BinaryRegionLocation;
}

export interface BinaryRegionLocation {
    byteOffset: number;
    byteLength: number;
}

export interface Driver {
    name: string;
    version?: string; // e.g., "0.3-beta4"
    semanticVersion?: string; // e.g., "2.4.0"
    rules: Rule[];
}

export interface Tool {
    driver: Driver
}

/*
export interface SarifResult {
    // {"ruleId":"EXAMPLE-VULN-001","level":"error","message":{"text":"Buffer overflow vulnerability detected."},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"binary://example-binary","uriBaseId":"%SRCROOT%"},"region":{"byteOffset":1024,"byteLength":128}},"properties":{"memoryAddress":"0x0040321A"}}]}]}
    ruleId: string;
    level: ResultLevel;
    message: {
        text:string;
    };
    locations: SarifLocation[];
}
    */

export interface ShortDescription {
    text: string // "Potential buffer overflow."
}

export interface SarifRule {
    driver :Driver;
    rule: Rule;
}

export interface Rule {
    "id": string; // "EXAMPLE-VULN-001",
    "name": string,
    "level": string,
    "shortDescription": ShortDescription | undefined,
    "fullDescription": ShortDescription | undefined,
    "helpUri": string, // "http://example.com/vulnerability/EXAMPLE-VULN-001"
}

export interface Run {
    tool: Tool;
    results?: Result[];
}

export interface SarifDocument {
    version: string; // e.g., "2.4.0"
    runs: Run[];
}


