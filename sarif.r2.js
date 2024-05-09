var sarifRegisterPlugin = (function () {
  const sarifTemplate = {
    $schema: 'http://json.schemastore.org/sarif-2.1.0',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'radare2',
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
    constructor () {
      this.doc = sarifTemplate;
      this.rulesLoaded = {};
    }

    /* load rules from a sarif file */
    loadRules (sarifDocument) {
      for (const run of sarifDocument.runs) {
	  try {
		  if (!run.tool || !run.tool.driver || !run.tool.driver.rules) {
			  continue;
		  }
          for (const rule of run.tool.driver.rules) {
            this.rulesLoaded[rule.id] = rule;
          }
	  } catch (e) {
		  console.error('loadRules', e);
	  }
      }
    }

    loadResults (sarifDocument) {
	  const r2baddr = parseInt(r2.cmd('e bin.baddr'));
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
            console.error(e);
          }
        }
      }
    }

    addRule (id) {
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

    reset () {
      this.doc.runs[0].results = [];
      this.doc.runs[0].tool.driver.rules = [];
    }

    addResult (ruleId, level, message, artifact, locations) {
      if (!this.addRule(ruleId)) {
        console.error('Invalid rule id: ' + ruleId);
        return false;
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
      return true;
    }

    toString () {
      return JSON.stringify(this.doc, null, 2) + '\n';
    }

    toScript () {
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
    }
  }

  function sarifTest () {
    const s = new R2Sarif();
    s.addResultOverflow('/bin/ls', 'buffer overflow detected', [
      { va: 0x804804, pa: 0x804, sz: 32 }
    ]);
    console.log(s.toString());
    console.log(s.toScript());
  }

  function sarifRegisterPlugin () {
    const sarif = new R2Sarif();
    function sarifCommand (args) {
      function sarifHelp () {
        console.log('sarif [action] [arguments]');
        console.log('sarif -h, help              - show this help message (-h)');
        console.log('sarif -a, add [r] [c]       - add a new sarif finding');
        console.log('sarif -aw,-ae,-an [r] [c]   - add warning, error or note');
        console.log('sarif -i, import [file]     - import sarif info from given file');
        console.log('sarif -e, export [file]     - export sarif findings into given file or stdout');
        console.log('sarif -r, r2|script         - generate r2 script with loaded sarif info');
        console.log('sarif -R, reset             - reset reported findings list');
        console.log('sarif -l, rules ([file])    - list or load rules from file');
      }
      function sarifLoadRules (fileName) {
        const sarifObject = r2.cmdj(`cat ${fileName}`);
        sarif.loadRules(sarifObject);
      }
      function sarifLoadResults (fileName) {
        const sarifObject = r2.cmdj(`cat ${fileName}`);
        sarif.loadRules(sarifObject);
        sarif.loadResults(sarifObject);
      }
      function listRules () {
        const res = [];
        for (const ruleId of Object.keys(sarif.rulesLoaded)) {
          const rule = sarif.rulesLoaded[ruleId];
          res.push(`- ${ruleId}`);
          try {
	  const desc = rule.fullDescription.text;
            res.push(`  - description: ${desc}`);
          } catch (e) {}
          try {
	  const level = rule.defaultConfiguration.level;
            res.push(`  - level: ${level}`);
          } catch (e) {}
        }
        return res.join('\n');
      }
      function sarifImport (fileName) {
        if (fileName === '') {
          console.log('Usage: sarif -i [filename]');
        } else {
          sarifLoadResults(fileName);
        }
      }
      function sarifExport () {
        console.log(sarif.toString());
      }
      function sarifScript (fileName) {
        r2.log(sarif.toScript());
      }
      function sarifAdd (level, args) {
        const arg = args.split(/ /);
        if (arg.length === 0) {
          console.error('Usage: sarif add[?] [id] [message]');
          return false;
        }
        const artifact = r2.cmd('o.').trim();
        const loc0 = {
          va: +r2.cmd('?v $$'),
          pa: r2.cmd('?p $$').trim(),
          sz: 1
        };
        const locations = [loc0];
        const ruleId = arg[0];
        const rule = sarif.rulesLoaded[ruleId];
        const comment = arg.length > 1 ? arg[1] : '';
        if (level === null) {
          try {
            level = rule.defaultConfiguration.level;
          } catch (err) {
            level = 'warning';
          }
        }
        if (!sarif.addResult(ruleId, level, comment, artifact, locations)) {
          console.error('Cannot add result');
        }
      }
      let arg = args.substr('sarif'.length).trim();
      const space = arg.indexOf(' ');
      let action = arg.trim();
      if (space !== -1) {
        action = arg.substr(0, space);
        arg = arg.substr(space + 1);
      } else {
        arg = '';
      }
      switch (action) {
        case '':
        case '?':
        case '-h':
        case 'help':
          sarifHelp();
          break;
        case '-a':
        case 'add':
          sarifAdd(null, arg);
          break;
        case '-aw':
        case 'addw':
          sarifAdd('warning', arg);
          break;
        case '-ae':
        case 'adde':
          sarifAdd('error', arg);
          break;
        case '-an':
        case 'addn':
          sarifAdd('note', arg);
          break;
        case '-l':
        case 'lr':
        case 'rules':
        case 'load-rules':
          if (arg) {
	  sarifLoadRules(arg);
          } else {
	  r2.log(listRules());
          }
          break;
        case '-i':
        case 'import':
          sarifImport(arg);
          break;
        case '-j':
        case '-e':
        case 'export':
          sarifExport(arg);
          break;
        case '*':
        case '-r':
        case 'r2':
        case 'script':
          sarifScript(arg);
          break;
        case '-R':
        case 'reset':
          sarif.reset();
          break;
        default:
          console.error('Unknown action');
          break;
      }
    }
    r2.unload('core', 'sarif');
    r2.plugin('core', function () {
      function coreCall (cmd) {
        if (cmd.startsWith('sarif')) {
          try {
            sarifCommand(cmd);
          } catch (e) {
            console.error(e);
          }
          return true;
        }
        return false;
      }
      return {
        name: 'sarif',
        license: 'MIT',
        desc: 'support importing and exporting sarif format',
        call: coreCall
      };
    });
  }
  return sarifRegisterPlugin;
})();
sarifRegisterPlugin();
