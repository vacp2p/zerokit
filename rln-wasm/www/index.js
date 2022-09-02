import * as rln from "rln-wasm";
import * as wc from "./witness_calculator"
import * as files from './files'

rln.init_panic_hook();

function _base64ToUint8Array(base64) {
    var binary_string = window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes;
}

function _concatenate(resultConstructor, ...arrays) {
    let totalLength = 0;
    for (const arr of arrays) {
        totalLength += arr.length;
    }
    const result = new resultConstructor(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}


function serializeMessage(uint8Msg, memIndex, epoch, idKey) {
    // calculate message length
    const msgLen = Buffer.allocUnsafe(8);
    msgLen.writeUIntLE(uint8Msg.length, 0, 8);

    // Converting index to LE bytes
    const memIndexBytes = Buffer.allocUnsafe(8)
    memIndexBytes.writeUIntLE(memIndex, 0, 8);

    // [ id_key<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
    return _concatenate(Uint8Array, idKey, memIndexBytes, epoch, msgLen, uint8Msg )
}

const verifKeyUint8Array = _base64ToUint8Array(files.verification_key);
const zkeyUint8Array = _base64ToUint8Array(files.zkey);
const circomUint8Array = _base64ToUint8Array(files.rln_wasm);


wc(circomUint8Array).then(async witnessCalculator => {
    // Test valid proof
    let rlnInstance = rln.newRLN(20, zkeyUint8Array, verifKeyUint8Array); // TODO: handle error

    let memKeys = rln.generateMembershipKey(rlnInstance); // TODO: handle error

    // TODO: convert memKeys to an object with IDCommitment and IDKey
    let IDKey = memKeys.subarray(0, 32)
    let IDCommitment = memKeys.subarray(32)

    console.log("IDKey", IDKey, "IDCommitment", IDCommitment)

    //peer's index in the Merkle Tree
    const index = 5

    // Create a Merkle tree with random members
    for (let i = 0; i < 10; i++) {
        if (i == index) {
            // insert the current peer's pk
            let result = rln.insertMember(rlnInstance, IDCommitment); // TODO: error handling
        } else {
            // create a new key pair
            let memKeys = rln.generateMembershipKey(rlnInstance); // TODO: handle error
            let IDCommitment = memKeys.subarray(32)
            let result = rln.insertMember(rlnInstance, IDCommitment);
        }
    }

    // prepare the message
    let uint8Msg = Uint8Array.from("Hello World".split("").map(x => x.charCodeAt()));

    // setting up the epoch (With 0s for the test)
    const epoch = new Uint8Array(32);

    // serializing the message ======
    let serialized_msg = serializeMessage(uint8Msg, index, epoch, IDKey);
       
    console.log("Serialized Message", serialized_msg)

    let rlnWitness = rln.getSerializedRLNWitness(rlnInstance, serialized_msg);
    console.log("Serialized RLN witness", rlnWitness)

    //  obtaining inputs that will be sent to circom witness calculator
    let inputs = rln.RLNWitnessToJson(rlnInstance, rlnWitness);
    console.log("Inputs for Circom", inputs);

    // calculate withness
    let calculatedWitness = await witnessCalculator.calculateWitness(inputs, false) // no sanity check being used in zerokit
    console.log("Calculated Witness", calculatedWitness)
    
    // generate proof
    console.log("Generating proof...");
    console.time("proof_gen_timer");
    let proofRes = rln.generate_rln_proof_with_witness(rlnInstance, calculatedWitness, rlnWitness);
    console.timeEnd("proof_gen_timer");
    console.log("Proof", proofRes)
    
    // verify the proof
    console.time("proof_verif_timer");
    let verifResult = rln.verifyProof(rlnInstance, proofRes);
    console.timeEnd("proof_verif_timer");
    console.log("Proof verification", verifResult);

});

