const fs = require("fs");

// Utils functions for loading circom witness calculator and reading files from test

module.exports = {
    read_file: function (path) {
        return fs.readFileSync(path);
    },

    calculateWitness: async function(circom_path, inputs){
        const wc = require("resources/witness_calculator.js");
        const wasmFile = fs.readFileSync(circom_path);
        const wasmFileBuffer = wasmFile.slice(wasmFile.byteOffset, wasmFile.byteOffset + wasmFile.byteLength);
        const witnessCalculator = await wc(wasmFileBuffer);
        const calculatedWitness = await witnessCalculator.calculateWitness(inputs, false);
        return JSON.stringify(calculatedWitness, (key, value) => typeof value === "bigint" ? value.toString() : value);
    }
}
