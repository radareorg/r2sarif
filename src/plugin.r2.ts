import { SarifDocument,  Driver, BinaryLocation, ResultLevel, Rule, Result, isValidLevel } from "./sarif/types.js";
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
| json      merge and dump all sarif documents together in json format
| docs      list all loaded documents
| rules     list rules from all documents or the selected one
| drivers   list all drivers available
| results   list all the results/findings from loaded documents
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

    unloadSarif(args: string[]) : boolean {
        if (args.length === 1) {
            const documentIndex = parseInt(args[0]);
            let newDocs : SarifDocument[]= [];
            let newPaths : string[] = [];
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

    toString() : string {
        const sarif = this.currentDocument.getSarif();
        if (sarif instanceof Error) {
            r2.error(sarif.toString());
            return "";
        }
        return JSON.stringify(sarif, null, 2);
    }

    toScript() : string {
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
        const script : string[] = [];
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
        /*
      let script = '# r2sarif script\n';
      const results = this.doc.runs[0].results;
      let counter = 0;
      for (const res of results) {
        let text = '';
        if (res && res.properties && res.properties.additionalProperties) {
          text = res.properties.additionalProperties.value;
        } else {
          text = res.message.text;
        }
        for (const loc of res.locations) {
          const address = loc.properties.memoryAddress;
          const size = loc.physicalLocation.region.byteLength;
          const ruleId = res.ruleId;
          // script += `CC ${ruleId}:${text} @ ${address}\n`;
          const addr = r2.cmd(`?v ${address}`).trim();
          script += `# ${text} @ ${addr}\n`;
          // TODO: detect when there are two comments in the same address
          if (res.ruleId === 'COMMENTS') {
	  const comment = `${text}`;
            script += `CC ${comment} @ ${address}\n`;
          } else {
	  const comment = `${ruleId}:${text}`;
            script += `CC ${comment} @ ${address}\n`;
            script += `f sarif.${counter} ${size} ${address}\n`;
          }
          counter++;
        }
      }
      return script;
      */
    }
    loadSarif(args: string[]) : boolean {
        if (args.length === 1) {
            const [fileName] = args;
            const data = readFileSync(fileName)
            if (data instanceof Error) {
                r2.error("Error: " + data);
                return false;
            }
            const doc = this.sf.parse(data);
            if (doc instanceof Error) {
                r2.error("Error parsing "+ doc);
                return false;
            }
            this.docs.push(doc);
            this.paths.push(fileName);
            r2.error("Document loaded. Use 'sarif list'")
        } else {
            r2.error("Usage: sarif load <sarif file>");
        }
        return true;
    }
    selectDriver(index: number) : boolean {
        if (index === -1) {
            this.currentDriverIndex = -1;
            this.currentDriver = null;
            return true;
        }
        const drivers = this.listDrivers();
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
          const sel = (index === this.currentDriverIndex)? "* ": "  ";
          const ver = driver.semanticVersion? driver.semanticVersion: driver.version? driver.version: ""
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

    listDrivers() : Driver[] {
        var res : Driver[] = [];
        let count = 0;
        for (const doc of this.docs) {
            for (const run of doc.runs) {
                const driver = run.tool.driver;
                const driverCount = count++;
                this.listDriver(driverCount, driver);
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
    listResults() : Result[] {
        var res : Result[]= [];
        for (const doc of this.docs) {
            for (const run of doc.runs) {
                if (run.results) {
                for (const res of run.results) {
                    r2.log(res.ruleId)
                }
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
            ? rule.name: "");
        const line = tabulateText([rule.id, text],[20, 40]);
        r2.log(line);
    }
    listRulesForDriver(driver: Driver) : Rule[] {
        var res: Rule[] = [];
        // r2.log("# Rules for Driver: " + driver.name + " (" + driver.semanticVersion + ")")
        for (const rule of driver.rules) {
            this.listRule(rule);
            res.push(rule);
        }
        return res;
    }
    listRules() : Rule[] {
        if (this.currentDriver !== null) {
            return this.listRulesForDriver(this.currentDriver);
        }
        var res :Rule[] = [];
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

    add(level: ResultLevel, ruleId: string, messageText: string) : boolean{
        if (this.currentDriver === null) {
            r2.error("No driver selected");
            return false;
        }
        const rules = this.listRulesForDriver(this.currentDriver);
        for (const rule of rules) {
            if (rule.id === ruleId) {
                const result : Result = {
                    ruleId: ruleId,
                    message: {
                        text: messageText
                    },
                    level: level,
                    locations: []
                };
                const loc : BinaryLocation = {
                    physicalLocation: {
                        artifactLocation: {
                            uri: "binary://example-binary",
                            uriBaseId: "%SRCROOT%"
                        },
                        region: {
                            byteOffset: 1024,
                            byteLength: 128
                        }
                    },
                    properties: {
                        memoryAddress: "123"
                    }
                }
                result.locations.push(loc);
                this.currentDocument.addResult(result);
                // this.currentRun = this.currentDocument.appendRun(this.currentDriver.name, this.currentDriver.version);
                // this.currentDriver.rules.push(rule);
                // this.currentDriver.rules.push(result);
                /*
                            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "binary://example-binary",
                  "uriBaseId": "%SRCROOT%"
                },
                "region": {
                  "byteOffset": 1024,
                  "byteLength": 128
                }
              },
              "properties": {
                "memoryAddress": "0x0040321A"
              }
            }

            */
                return true;
            }
        }
        return true;
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
                const ruleId = args[2];
                const textMessage = args.slice(3).join (" ");
                if (isValidLevel(levelType)) {
                    r2s.add(levelType, ruleId, textMessage);
                }
            } else {
                r2.log("sarif add [type] [id] [message]")
                r2.log("type = warning, error, note")
            }
            break;
        case 'addw':
        case '-aw':
            if (args.length === 3) {
                const ruleId = args[1];
                const textMessage = args.slice(2).join (" ");
                r2s.add("warning", ruleId, textMessage);
            } else {
                r2.error("sarif addw [id] [message]")
            }
            break;
        case 'adde':
        case '-ae':
            if (args.length === 3) {
                const ruleId = args[1];
                const textMessage = args.slice(2).join (" ");
                r2s.add("error", ruleId, textMessage);
            } else {
                r2.log("sarif adde [id] [message]")
            }
            break;
        case 'addn':
        case '-an':
            if (args.length === 3) {
                const ruleId = args[1];
                const textMessage = args.slice(2).join (" ");
                r2s.add("note", ruleId, textMessage);
            } else {
                r2.log("sarif addn [id] [message]")
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
    r2.plugin("core", function() {
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
