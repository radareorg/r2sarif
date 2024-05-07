// SARIF Document Structure (simplified)

export interface Result {
    level: ResultLevel;
    message: string;
    location: Location; // (optional) file, line, column information
    relatedLocations?: Location[]; // (optional) additional locations
}

export type ResultLevel = "error" | "warning" | "note" | "none";

export interface SourceLocation {
    fileUri: string;
    lineNumber: number;
    columnNumber: number;
}

export class SarifError extends Error {
    constructor(message: string) {
        super(message);
        this.name = this.constructor.name;
    }
}

export interface BinaryLocation {
    physicalLocation: BinaryPhysicalLocation;
    properties: BinaryLocationProperties;
}

export type Location = SourceLocation | BinaryLocation | SourceLineLocation;

export interface BinaryLocationProperties {
    memoryAddress: string;
}

export type SourceLineLocation = Partial<
    Pick<SourceLocation, 'fileUri'> &
    Pick<SourceLocation, 'lineNumber'> &
    { columnNumber: 0 }>;

export interface BinaryArtifactLocation {
    uri: string; // "binary://example-binary",
    uriBaseId: string; // "%SRCROOT%"
}

export interface BinaryPhysicalLocation {
    artifactLocation: BinaryArtifactLocation;
    region: BinaryRegionLocation;
}

export interface BinaryRegionLocation {
    startByteOffset: number;
    byteLength: number;
}

export interface Tool {
    driver: {
        name: string;
        version: string;
        rules: [];
    };
}

export interface shortDescription {
    text: string // "Potential buffer overflow."
}

export interface Rule {
    "id": string; // "EXAMPLE-VULN-001",
    "shortDescription": shortDescription,
    "helpUri": string, // "http://example.com/vulnerability/EXAMPLE-VULN-001"
}

export interface Run {
    tool: Tool;
    results: Result[];
}

export interface SarifDocument {
    version: string; // e.g., "2.4.0"
    runs: Run[];
}