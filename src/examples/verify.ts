import { verifySarif, readFileSync } from "../sarif/utilsverify.js";

const data: any = JSON.parse(readFileSync("test-sarif.json", "utf-8"));
const result = verifySarif(data);
if (result === true) {
    console.log("SARIF document is valid");
} else {
    console.error(result);
    for (let err of result) {
        console.log(err.instancePath + " " + err.message);
    }
}