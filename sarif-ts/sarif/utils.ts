import { SourceLineLocation, SourceLocation, BinaryLocation } from "./types";


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