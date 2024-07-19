// XXX UNUSED CODE
// XXX we can remove this file entirely

import { sarifTemplate } from "./template.js";
import { Rule, SarifDocument, SarifError } from "./types.js";

class Sarif {
  doc: any;
  rulesLoaded: Map<string, Rule>;

  constructor() {
    this.doc = sarifTemplate;
    this.rulesLoaded = new Map<string, Rule>;
  }

  /* load rules from a sarif document */
  loadRules(sarifDocument: any) {
    // unused
    for (const run of sarifDocument.runs) {
      // maybe this should be a warning.. and loadingRules should return a LoadingReport instead
      if (!run.tool || !run.tool.driver || !run.tool.driver.rules) {
        // return new SarifError("Missing driver rules");
        continue;
      }
      for (const rule of run.tool.driver.rules) {
        this.rulesLoaded.set(rule.id, rule);
      }
    }
  }

  loadResults(sarifDocument: any) : Error | undefined {
    // unused
    const r2baddr = 0;
    for (const run of sarifDocument.runs) {
      let baddr = 0;
      if (!run.artifacts) {
        continue;
      }
      for (const art of run.artifacts) {
        // console.log(art.location.uri);
        // console.log(art.sourceLanguage);
        // console.log(art.properties.additionalProperties);
        baddr = parseInt('0x' + art.properties.additionalProperties.imageBase);
      }
      for (const res of run.results) {
        const ruleId = res.ruleId;
        const level = res.level;
        let message = '';
        if (res && res.properties && res.properties.additionalProperties) {
          message = res.properties.additionalProperties.value;
        } else {
          message = res.message.text;
        }
        try {
          const flows = res.codeFlows;
          console.log(flows);
        } catch (e) {
          console.error(e);
          // ignore
        }
        const loc0 = res.locations[0];
        try {
          // console.log(JSON.stringify(loc0, null, 2));
          const phyloc = loc0.physicalLocation;
          const artifact = (phyloc && phyloc.artifactLocation) ? phyloc.artifactLocation.uri : '';
          const locations = [];
          if (loc0 && loc0.properties && loc0.properties.memoryAddress) {
            locations.push({
              va: loc0.properties.memoryAddress,
              pa: phyloc.region.byteOffset,
              sz: phyloc.region.byteLength
            });
          } else {
            const pa = phyloc.address.absoluteAddress;
            const sz = phyloc.address.length;
            let va = pa;
            if (baddr > 0) {
              if (va >= baddr) {
                va -= baddr;
              }
              va += r2baddr;
            }
            locations.push({
              va: va,
              sz: sz,
              pa: pa
            });
          }
          this.addResult(ruleId, level, message, artifact, locations);
        } catch (e) {
          return e;
        }
      }
    }
  }

  addRule(id) {
    if (this.doc.runs[0].tool.driver.rules.filter((x) => x.id === id).length !== 0) {
      return true;
    }
    const rule = this.rulesLoaded[id];
    if (rule) {
      this.doc.runs[0].tool.driver.rules.push(rule);
      return true;
    }
    return false;
  }

  reset() {
    this.doc.runs[0].results = [];
    this.doc.runs[0].tool.driver.rules = [];
  }

  addResult(ruleId, level, message, artifact, locations) : Error | undefined {
    if (!this.addRule(ruleId)) {
      return new Error ('Invalid rule id: ' + ruleId);
    }
    const sarifLocations = [];
    const result = {
      ruleId: ruleId,
      level: level,
      message: {
        text: message
      },
      locations: []
    };
    const locationTemplate = {
      physicalLocation: {
        artifactLocation: {
          uri: 'binary://' + artifact,
          uriBaseId: '%SRCROOT%'
        },
        region: {
          byteOffset: locations,
          byteLength: 128
        }
      },
      properties: {
        memoryAddress: '0x0040321A'
      }
    };
    for (const loc of locations) {
      const myLoc = locationTemplate;
      myLoc.physicalLocation.region = {
        byteOffset: loc.pa,
        byteLength: loc.sz
      };
      myLoc.properties = {
        memoryAddress: loc.va
      };
      result.locations.push(myLoc);
    }
    this.doc.runs[0].results.push(result);
  }

 /**
 * Converts the SARIF document to a JSON string with 2 spaces of indentation.
 * @returns {string} The SARIF document as a JSON string.
 */
  toString() {
    return JSON.stringify(this.doc, null, 2) + '\n';
  }

  /**
 * Generates a Radare2 script from the SARIF document.
 * The script includes comments and flags for the identified issues in the SARIF document.
 * @returns {string} The Radare2 script.
 */
  toRadareScript() {
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
        const addr = address;
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
  }
}
