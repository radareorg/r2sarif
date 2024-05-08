import { readFileSync} from "fs";
import { verifySarif } from "../sarif/utils.js";

const data : any = readFileSync("test-sarif.json");
const result = verifySarif(JSON.parse(data));