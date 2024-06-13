import { SarifGenerator, SarifRun } from "./sarif/generator.js";
import { SarifParser } from "./sarif/parser.js"
import { SarifDocument,  Driver, ResultLevel, Rule, Result, isValidLevel } from "./sarif/types.js";
import { tabulateText } from "./sarif/utilsgen.js";


interface R2Pipe {
    unload(module: string, name: string): void;
    plugin(module: string, def: any): void;
    cmd(command: string): string;
}
declare global {
    var r2: R2Pipe;
}

function readFileSync(fileName: string): string|Error {
    try {
        const data = r2.cmd("cat " + fileName);
        return data.trim();
    } catch (e) {
        return e;
    }
}

const pluginName = "sarif";

const sarifTemplate = {
    $schema: 'http://json.schemastore.org/sarif-2.1.0',
    version: '2.1.0',
    runs: [
        {
            tool: {
                driver: {
                    name: 'radare2',
                    version: '1.0.0',
                    semanticVersion: '1.0.0',
                    rules: [
                    ]
                }
            },
            results: [
            ]
        }
    ]
};

class R2Sarif {
    sf: SarifParser;
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
                console.error("Cannot parse this sarif document");
                console.error(res);
            } else {
                console.error("ok");
            }
        } catch (err) {
            console.error(err);
        }
    }
    importSarif(args: string[]) : boolean {
        // load this stuff in here
        if (args.length === 1) {
            const [fileName] = args;
            const data = readFileSync(fileName)
        ///    console.log(data);
            if (data instanceof Error) {
                console.log("Error: " + data);
                return false;
            }
            const doc = this.sf.parse(data);
            if (doc instanceof Error) {
                console.log("Error parsing "+ doc);
                return false;
            }
            this.docs.push(doc);
            console.log("Document loaded. Use 'sarif list'")
        }
        return true;
    }
    selectDriver(index: number) : boolean {
        if (index == -1) {
            this.currentDriverIndex = -1;
            this.currentDriver = null;
            return true;
        }
        const drivers = this.listDrivers();
        if (index < drivers.length) {
            this.currentDriver = drivers[index];
            this.currentDriverIndex = index;
            console.log("Selected driver:")
            this.listDriver(index, this.currentDriver);
            return true;
        }
        console.error("Invalid index. Run: sarif list drivers");
        return false;
    }

    listDriver(index: number, driver: Driver) {
          const sel = (index == this.currentDriverIndex)? "* ": "  ";
          console.log(sel, index, driver.name, driver.semanticVersion)
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
            console.log(JSON.stringify(doc));
        }
    }
    listResults() : Result[] {
        var res : Result[]= [];
        for (const doc of this.docs) {
            for (const run of doc.runs) {
                for (const res of run.results) {
                    console.log(res.ruleId)
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
            : "");
        const line = tabulateText([rule.id, text],[40, 40]);
        console.log(line);
    }
    listRulesForDriver(driver: Driver) : Rule[] {
        var res: Rule[] = [];
        console.log("From driver: " + driver.name + "  " + driver.semanticVersion)
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
        this.docs = []
        this.currentDriver = null;
        this.currentDriverIndex = -1;
    }

    add(level: ResultLevel, ruleId: string, messageText: string) : boolean{
        if (this.currentDriver === null) {
            console.error("No driver selected");
            return false;
        }
        const rules = this.listRulesForDriver(this.currentDriver);
        for (const rule of rules) {
            if (rule.id === ruleId) {
                const result = {
                    ruleId: ruleId,
                    message: {
                        text: messageText
                    },
                    level: level
                }
             //   this.currentRun = this.currentDocument.appendRun(this.currentDriver.name, this.currentDriver.version);
                // this.currentDriver.rules.push(rule);
                // this.currentDriver.rules.push(result);
                return true;
            }
        }
        console.log("TODO ADD");
        return true;
    }
}

function showHelp() {
    const println = console.log;
    println(`Usage: sarif [action] [args...]
sarif alias [newalias]  - create an alias for the sarif command
sarif help              - show this help message (-h)
sarif import [file]     - import sarif info from given file
sarif list [help]       - list drivers, rules and results
sarif reset             - unload all documents
sarif select [N]        - select the nth driver
TODO
sarif -a, add [r] [c]       - add a new sarif finding
sarif -aw,-ae,-an [r] [c]   - add warning, error or note'
sarif -e, export [file]     - export sarif findings into given file or stdout
sarif -r, r2|script         - generate r2 script with loaded sarif info
`);
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
            if (args.length === 5) {
                const levelType = args[1];
                const ruleId = args[2];
                const textMessage = args.slice(3).join (" ");
                if (isValidLevel(levelType)) {
                    r2s.add(levelType, ruleId, textMessage);
                }
            } else {
                console.log("sarif add [type] [id] [message]")
                console.log("type = warning, error, note")
                //showHelp();
            }
            break;
        case 'addw':
        case '-aw':
            if (args.length === 4) {
                const ruleId = args[1];
                const textMessage = args.slice(2).join (" ");
                r2s.add("warning", ruleId, textMessage);
            } else {
                console.log("sarif addw [id] [message]")
            }
            break;
        case 'adde':
        case '-ae':
            if (args.length === 4) {
                const ruleId = args[1];
                const textMessage = args.slice(2).join (" ");
                r2s.add("error", ruleId, textMessage);
            } else {
                console.log("sarif adde [id] [message]")
            }
            break;
        case 'addn':
        case '-an':
            if (args.length === 4) {
                const ruleId = args[1];
                const textMessage = args.slice(2).join (" ");
                r2s.add("note", ruleId, textMessage);
            } else {
                console.log("sarif addn [id] [message]")
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
                console.log(r2s.alias);
            }
            break;
        case '-c':
        case "clean":
            r2s.reset();
            break;
        case '-s':
        case 'select':
            if (args.length == 2) {
                r2s.selectDriver(Number.parseInt(args[1]));
            } else {
                r2s.listDrivers();
            }
            break;
        case '-l':
        case "ls":
        case "list":
            if (args.length == 2) {
                const arg = args[1];
                console.log(args[1]);
                switch (arg) {
                case "-R":
                case "rules":
                    r2s.listRules();
                    break;
                case "-j":
                case "json":
                    r2s.listJson();
                    break;
                case "-r":
                case "results":
                    r2s.listResults();
                    break;
                case "-d":
                case "drivers":
                    r2s.listDrivers();
                    break;
                default:
                    console.log("sarif list [json|rules|drivers|results] or [-j, -R, -d, -r]")
                    break;
                }
            } else {
                console.log("sarif list [json|rules|drivers|results] or [-j, -R, -d, -r]")
                // r2s.listRules();
            }
            break;
        case '-i':
        case 'import':
        case 'load':
          r2s.importSarif(args.slice(1));
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
                console.error(e.stack);
                console.error(e);
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
    console.error(e);
    console.error(e.stack);
}
