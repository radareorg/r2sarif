import { SourceLineLocation, SourceLocation, BinaryLocation } from "./types";

import { readFileSync } from "fs";

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
                byteOffset: offset,
                byteLength: length
            }
        },
        properties: {
            memoryAddress
        }
    };
}

export function tabulateText(columns: string[], columnWidths: number[]) : string {
    // implement this
    let resultingText = "";
    let col = 0;
    for (const column of columns) {
        const columnWidth = columnWidths[col++];
        resultingText += column.padEnd(columnWidth);
    }
    return resultingText;
}