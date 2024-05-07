export const sarifSchemeVersion = "2.1.0";

// TODO: move into utils
export const sarifRadareTemplate = {
  $schema: 'http://json.schemastore.org/sarif-' + sarifSchemeVersion,
  version: sarifSchemeVersion,
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


// TODO: move into utils
export const sarifTemplate = {
  $schema: 'http://json.schemastore.org/sarif-' + sarifSchemeVersion,
  version: sarifSchemeVersion,
  runs: [ ]
};

