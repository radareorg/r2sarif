import { StringMap, SarifDocument, Driver, ResultKind, BinaryLocation, ResultLevel, Rule, Result, isValidLevel, isValidKind } from "./sarif/types.js";
import { SarifGenerator, SarifRun } from "./sarif/generator.js";
import { tabulateText } from "./sarif/utilsgen.js";
import { SarifParser } from "./sarif/parser.js"

const pluginName = "sarif";
const pluginVersion = "0.0.1";

interface R2Pipe {
    unload(module: string, name: string): void;
    plugin(module: string, def: any): void;
    cmd(command: string): string;
    log(msg: string);
    error(msg: string);
}

declare global {
    var r2: R2Pipe;
    function b64(string): string;
}

function readFileSync(fileName: string): string | Error {
    try {
        const data = r2.cmd("cat " + fileName);
        return data.trim();
    } catch (e) {
        return e;
    }
}

const sarifListHelp = `sarif list [type]  # see 'sarif select'
| docs      list all loaded documents
| drivers   list all drivers available
| json      merge and dump all sarif documents together in json format
| r2        list results from all documents loaded as r2 commands
| results   list all the results/findings from loaded documents
| rules     list rules from all documents or the selected one
`.trim();

class R2Sarif {
    version: string = pluginVersion;
    sf: SarifParser;
    paths: string[] = [];
    docs: SarifDocument[] = [];
    currentDriver: Driver | null = null;
    currentDriverIndex: number = -1;
    alias: string | null = null;
    currentDocument: SarifGenerator;
    currentRun: SarifRun;

    constructor() {
        this.sf = new SarifParser();
        this.alias = null;
        this.currentDocument = new SarifGenerator();
    }
    load() {
        try {
            const res = this.sf.parse("{}");
            if (res instanceof Error) {
                r2.error("Cannot parse this sarif document");
                r2.error(res.toString());
            } else {
                r2.error("ok");
            }
        } catch (err) {
            r2.error(err);
        }
    }

    unloadSarif(args: string[]): boolean {
        if (args.length === 1) {
            const documentIndex = parseInt(args[0]);
            let newDocs: SarifDocument[] = [];
            let newPaths: string[] = [];
            let count = 0;
            for (const doc of this.docs) {
                if (count++ === documentIndex) {
                    r2.error("Document " + count + " unloaded. Run 'sarif select' again please.");
                } else {
                    newDocs.push(doc);
                    newPaths.push(this.paths[count]);
                }
            }
            this.docs = newDocs;
            this.paths = newPaths;
            this.selectDriver(-1);
        }
        return true;
    }

    toString(): string {
        const sarif = this.currentDocument.getSarif();
        if (sarif instanceof Error) {
            r2.error(sarif.toString());
            return "";
        }
        return JSON.stringify(sarif, null, 2);
    }

    toScript(): string {
        const sarif = this.currentDocument.getSarif();
        if (sarif instanceof Error) {
            r2.error(sarif.toString());
            return "";
        }
        const s = this.currentDocument.getSarif();
        if (s instanceof Error) {
            r2.error(s.toString());
            return "";
        }
        const script: string[] = [];
        script.push("# SARIF script for radare2");
        let counter = 0;
        for (const run of s.runs) {
            if (run.results) {
                run.results.forEach((res) => {
                    // script.push(JSON.stringify(res, null, 4));
                    for (const loc of res.locations) {
                        if ((loc as BinaryLocation).properties) {
                            const bloc = loc as BinaryLocation;
                            // r2.log(loc.physicalLocation.artifactLocation.uri);
                            const addr = bloc.properties.memoryAddress;
                            const size = bloc.physicalLocation.region.byteLength;
                            const rule = res.ruleId;
                            let text;
                            if (res && res.properties && res.properties.additionalProperties) {
                                text = res.properties.additionalProperties.value;
                            } else {
                                text = res.message.text;
                            }
                            const at = r2.cmd(`?v ${addr}`).trim();
                            script.push(`# ${text} @ ${at} / ${size} ${rule}`);
                            script.push(`CC ${rule}:${text} @ ${at}`); // encode in base64
                            script.push(`f sarif.${counter} ${size} ${at}`);
                        }
                    }
                });
            }
        }
        return script.join("\n");
    }

    loadSarif(args: string[]): boolean {
        if (args.length === 1) {
            const [fileName] = args;
            const data = readFileSync(fileName)
            if (data instanceof Error) {
                r2.error("Error: " + data);
                return false;
            }
            const doc = this.sf.parse(data);
            if (doc instanceof Error) {
                r2.error("Error parsing " + doc);
                return false;
            }
            this.docs.push(doc);
            this.paths.push(fileName);
            this.selectDriver(this.listDrivers(true).length - 1);
            r2.error("Document loaded and driver selected. Use 'sarif list'")
        } else {
            r2.error("Usage: sarif load <sarif file>");
        }
        return true;
    }

    selectDriver(index: number): boolean {
        if (index === -1) {
            this.currentDriverIndex = -1;
            this.currentDriver = null;
            return true;
        }
        const drivers = this.listDrivers(true);
        if (index < drivers.length) {
            this.currentDriver = drivers[index];
            this.currentDriverIndex = index;
            r2.log("Selected driver:")
            this.listDriver(index, this.currentDriver);
            this.currentDocument.selectDriver(this.currentDriver);
            return true;
        }
        r2.error("Invalid index. Run: sarif list drivers");
        return false;
    }

    listDriver(index: number, driver: Driver) {
        const sel = (index === this.currentDriverIndex) ? "* " : "  ";
        const ver = driver.semanticVersion ? driver.semanticVersion : driver.version ? driver.version : ""
        const text = tabulateText([sel, index.toString(), driver.name, ver], [2, 4, 20, 20]);
        r2.log(text);
    }

    listDocs() {
        let count = 0;
        for (const doc of this.docs) {
            const docPath = this.paths[count];
            r2.log(count + " " + docPath);
            for (const run of doc.runs) {
                r2.log(" + " + run.tool.driver.name + " " + run.tool.driver.semanticVersion);
            }
            count++;
        }
    }

    listDrivers(silent?: boolean): Driver[] {
        var res: Driver[] = [];
        let count = 0;
        for (const doc of this.docs) {
            for (const run of doc.runs) {
                const driver = run.tool.driver;
                const driverCount = count++;
                if (!silent) {
                    this.listDriver(driverCount, driver);
                }
                res.push(driver);
            }
        }
        return res;
    }
    listJson() {
        for (const doc of this.docs) {
            r2.log(JSON.stringify(doc));
        }
    }

    getRulesAsMap(): StringMap {
        const myMap: StringMap = new Map<string,string>();
        const rules = this.listRules(true);
        for (const rule of rules) {
            if (myMap.get(rule.id)) {
                r2.error("Duplicated RuleID: " + rule.id);
            }
            // const desc = rule.shortDescription?.text ?? rule.fullDescription?.text ?? "";
            myMap.set(rule.id, rule.name);
        }
        return myMap;
    }

    getAllResults() : Result[] {
        var allResults: Result[] = [];
        for (const doc of this.docs) {
            for (const run of doc.runs) {
                if (run.results) {
                    for (const res of run.results) {
                        allResults.push(res);
                    }
                }
            }
        }
        return allResults;
    }

    listResultsAsR2() {
        var res: Result[] = [];
        const ruleMap = this.getRulesAsMap();
        const results = this.getAllResults();
        const script : string[] = [];
        // TODO Find base address of all the artifacts involved
        for (const res of results) {
            if (!res.locations && !res.codeFlows) {
                console.error("This result has no locations or codeFlows " + res.ruleId);
                continue;
            }
            let addr = "";
            if (res.locations) {
                const bloc = res.locations[0] as BinaryLocation;
                addr = "0x" + bloc.physicalLocation.address?.absoluteAddress.toString(16);
            } else if (res.codeFlows) {
                for (const cf of res.codeFlows) {
                    for (const tf of cf.threadFlows) {
                        const tfloc = cf.threadFlows[0].locations[0];
                        addr = "0x" + tfloc.location.physicalLocation.address?.absoluteAddress.toString(16);
                        break;
                    }
                }
            }
            const desc = ruleMap.get(res.ruleId);
            const comment = `${res.ruleId}: ${desc}`;
            script.push(`'@${addr}'CC ${comment}`);
            // script.push("CC base64:" + b64(comment) + " @ " + addr);

            if (res.message) {
                let message: undefined|string = undefined;
                if (res.message.arguments) {
                    const args = res.message.arguments;
                    const arg0 = args[0];
                    args.shift();
                    const argText = args.join(", ");
                    message = `${arg0}(${argText})`;
                } else if (res.message.text) {
                    message = res.message.text;
                }
                if (message) {
                    // script.push("CC base64:" + b64(message) + " @ " + addr);
                    script.push(`'@${addr}'CC ${message}`);
                }
            }
            const codeflow : string[] = [];
            if (res.codeFlows !== undefined) {
                for (const cf of res.codeFlows) {
                    for (const tf of cf.threadFlows) {
                        for (const tfloc of tf.locations) {
                            let addr = "0x" + tfloc.location.physicalLocation.address?.absoluteAddress.toString(16);
                            codeflow.push(addr);
                        }
                    }
                }
            }
            if (codeflow.length > 0) {
                script.push("'abt+" + codeflow.join(" "));
            }
        }
        r2.log(script.join("\n"));
    }
    listResults(): Result[] {
        var res: Result[] = [];
        const ruleMap = this.getRulesAsMap();
        const results = this.getAllResults();
        for (const res of results) {
            let resultText = res.ruleId;
            const desc = ruleMap.get(res.ruleId);
            if (desc !== undefined) {
                resultText += " :: " + desc;
            }
            r2.log(resultText);
            if (res.message) {
                if (res.message.arguments) {
                    const args = res.message.arguments;
                    const arg0 = args[0];
                    args.shift();
                    r2.log("       :: " + arg0 + " (" + args.join(", ") + ")");
                } else if (res.message.text) {
                    r2.log("       :: " + res.message.text);
                }
            }
            if (res.codeFlows !== undefined) {
                for (const cf of res.codeFlows) {
                    for (const tf of cf.threadFlows) {
                        for (const tfloc of tf.locations) {
                            let addr = "0x" + tfloc.location.physicalLocation.address?.absoluteAddress.toString(16);
                            let relAddr = tfloc.location.physicalLocation.region.byteOffset;
                            let text = " - " + addr + " " + tfloc.module;
                            if (tfloc.location) {
                                const phys = tfloc.location.physicalLocation;
                                text += " " + phys.artifactLocation.uri;
                                text += " +" + relAddr;
                            }
                            r2.log(text);
                        }
                    }
                }
            } else if (res.locations) {
                for (const loc of res.locations) {
                    const bloc = loc as BinaryLocation;
                    let addr = "0x" + bloc.physicalLocation.address?.absoluteAddress.toString(16);
                    let relAddr = bloc.physicalLocation.region.byteOffset;
                    let text = " - " + addr + " module";
                    if (bloc.physicalLocation.region.byteOffset !== undefined) {
                        text += " +" + relAddr.toString();
                    }
                    r2.log(" - " + text);
                }
            }
        }
        return res;
    }
    listRule(rule: Rule) {
        const text = (rule.shortDescription
            ? rule.shortDescription.text
            : rule.fullDescription
                ? rule.fullDescription.text
                : rule.name
                    ? rule.name : "");
        const line = tabulateText([rule.id, text], [20, 40]);
        r2.log(line);
    }
    listRulesForDriver(driver: Driver, quiet?: boolean): Rule[] {
        if (quiet === true) {
            return driver.rules;
        }
        // r2.log("# Rules for Driver: " + driver.name + " (" + driver.semanticVersion + ")")
        for (const rule of driver.rules) {
            this.listRule(rule);
        }
        return driver.rules;
    }
    listRules(quiet? : boolean): Rule[] {
        if (this.currentDriver !== null) {
            return this.listRulesForDriver(this.currentDriver, quiet);
        }
        var res: Rule[] = [];
        for (const doc of this.docs) {
            for (const run of doc.runs) {
                const driver = run.tool.driver;
                res.push(...this.listRulesForDriver(driver));
            }
        }
        return res;
    }

    reset() {
        this.docs = [];
        this.paths = [];
        this.currentDriver = null;
        this.currentDriverIndex = -1;
    }

    add(level: ResultLevel, kind: ResultKind, ruleId: string, messageText: string): boolean {
        if (this.currentDriver === null) {
            r2.log("No driver selected");
            return false;
        }
        if (!isValidLevel(level)) {
            r2.log("Invalid result level: " + level);
            return false;
        }
        if (!isValidKind(kind)) {
            r2.log("Invalid result kind: " + kind);
            return false;
        }
        const rules = this.listRulesForDriver(this.currentDriver, true);
        const pa = Number(r2.cmd("?p $$"));
        const va = r2.cmd("?v $$").trim();
        const sz = Number(r2.cmd("ao~size[1]")); // b"));
        const fileName = r2.cmd("o.").trim();
        for (const rule of rules) {
            if (rule.id === ruleId) {
                const result: Result = {
                    ruleId: ruleId,
                    message: {
                        text: messageText
                    },
                    kind: kind,
                    level: level,
                    locations: []
                };
                const loc: BinaryLocation = {
                    physicalLocation: {
                        artifactLocation: {
                            uri: "binary://" + fileName,
                //            uriBaseId: "%SRCROOT%"
                        },
                        region: {
                            byteOffset: pa,
                            byteLength: sz
                        }
                    },
                    properties: {
                        memoryAddress: va.toString()
                    }
                }
                result.locations.push(loc);
                this.currentDocument.addResult(result);
                return true;
            }
        }
        return false;
    }
}

function showHelp() {
    const println = r2.log;
    println(`Usage: sarif [action] [args...]
sarif add [L] [id] [M]  - add a new result with selected driver
sarif alias [newalias]  - create an alias for the sarif command
sarif export            - export added rules as sarif json
sarif help              - show this help message (-h)
sarif list [help]       - list drivers, rules and results
sarif load [file]       - import sarif info from given file
sarif r2                - generate r2 script to import current doc results
sarif reset             - unload all documents
sarif select [N]        - select the nth driver
sarif unload [N]        - unload the nth document
sarif version           - show plugin version
`.trim());
}

function sarifCommand(r2s: R2Sarif, cmd: string): boolean {
    if (r2s.alias === null || !cmd.startsWith(r2s.alias)) {
        if (!cmd.startsWith(pluginName)) {
            return false;
        }
    }
    const args = cmd.slice(pluginName.length).trim().split(" ");
    if (args.length === 0) {
        showHelp()
    } else switch (args[0]) {
        case "":
        case "?":
        case "-h":
        case "help":
            showHelp();
            break;
        case "-a":
        case "add":
            if (args.length >= 4) {
                const levelType = args[1];
                const kind = args[2];
                const ruleId = args[3];
                const textMessage = args.slice(4).join(" ");
                if (!r2s.add(levelType, kind, ruleId, textMessage)) {
                    r2.log("sarif add failed");
                }
            } else {
                r2.log("sarif add [type] [kind] [ruleid] [message]")
                r2.log("type = warning, error, note")
                r2.log("kind = notApplicable, pass, fail, review, open, informational");
                r2.log("ruleid = run: sarif list rules");
                r2.log("message = associated comment represented as a space separated list of words");
            }
            break;
        case 'addw':
        case '-aw':
            if (args.length >= 3) {
                const kind = args[1]
                const ruleId = args[2];
                const textMessage = args.slice(3).join(" ");
                if (!r2s.add("warning", kind, ruleId, textMessage)) {
                    r2.error("addw invalid arguments");
		}
            } else {
                r2.error("sarif addw [kind] [id] [message]")
            }
            break;
        case 'adde':
        case '-ae':
            if (args.length >= 3) {
                const ruleId = args[1];
                const kind = args[2];
                const textMessage = args.slice(3).join(" ");
                r2s.add("error", kind, ruleId, textMessage);
            } else {
                r2.log("sarif adde [kind] [id] [message]")
            }
            break;
        case 'addn':
        case '-an':
            if (args.length >= 3) {
                const ruleId = args[1];
                const kind = args[2];
                const textMessage = args.slice(3).join(" ");
                r2s.add("note", kind, ruleId, textMessage);
            } else {
                r2.log("sarif addn [kind] [id] [message]")
            }
            break;
        case '-A':
        case 'alias':
            if (args.length === 2) {
                const newAlias = args[1];
                if (newAlias.startsWith("-")) {
                    r2s.alias = null;
                } else {
                    r2s.alias = args[1];
                }
            } else {
                if (r2s.alias) {
                    r2.log(r2s.alias);
                } else {
                    r2.error("Alias not defined");
                }
            }
            break;
        case '-c':
        case "clean":
            r2s.reset();
            break;
        case '-s':
        case 'select':
            if (args.length === 2) {
                r2s.selectDriver(Number.parseInt(args[1]));
            } else {
                r2s.listDrivers();
            }
            break;
        case '-l':
        case "ls":
        case "list":
            if (args.length === 2) {
                const arg = args[1];
                switch (arg) {
                    case "-R":
                    case "rul":
                    case "rules":
                        r2s.listRules();
                        break;
                    case "-j":
                    case "json":
                        r2s.listJson();
                        break;
                    case "-r":
                    case "res":
                    case "results":
                        r2s.listResults();
                        break;
                    case "r2":
                        r2s.listResultsAsR2();
                        break;
                    case "-d":
                    case "drv":
                    case "drivers":
                        r2s.listDrivers();
                        break;
                    case "docs":
                        r2s.listDocs();
                        break;
                    default:
                        r2.log(sarifListHelp);
                        break;
                }
            } else {
                r2.log(sarifListHelp);
            }
            break;
        case '-i':
        case 'import':
        case 'load':
            r2s.loadSarif(args.slice(1));
            break;
        case "unload":
            r2s.unloadSarif(args.slice(1));
            break;
        case "version":
        case "-V":
            r2.log(r2s.version);
            break;
        case "dump":
            r2.log(r2s.toString());
            break;
        case "r2":
            r2.log(r2s.toScript());
            break;
    }
    return true;
}

function registerSarifPlugin() {
    r2.unload("core", pluginName);
    r2.plugin("core", function () {
        const r2s = new R2Sarif();
        function coreCall(cmd: string) {
            try {
                return sarifCommand(r2s, cmd);
            } catch (e) {
                r2.error(e.stack);
                r2.error(e);
            }
        }
        return {
            name: pluginName,
            license: "MIT",
            desc: "Manage SARIF documents",
            call: coreCall
        }
    });
}

try {
    registerSarifPlugin();
} catch (e) {
    r2.error(e);
    r2.error(e.stack);
}
