# RLN wrapper

`cargo run` should produce a verified proof:

```
Proof: Proof { a: GroupAffine { x: Fp256(BigInteger256([8483808811394525823, 2911623124993487936, 965710634470565595, 371243954766865014])), y: Fp256(BigInteger256([705817196479998808, 17904136250720012753, 4190084222192764444, 7218570197435348])), infinity: false }, b: GroupAffine { x: QuadExtField { c0: Fp256(BigInteger256([5458988222411652552, 17182308780189183250, 14791331698105531271, 721079937701984589])), c1: Fp256(BigInteger256([7448529038603485276, 13923597709209930, 3309560575781216904, 880478657337970720])) }, y: QuadExtField { c0: Fp256(BigInteger256([15528177727577722078, 5558129266105870459, 2736358139645020298, 1495034096047214880])), c1: Fp256(BigInteger256([17682510405762186416, 10008291815399475705, 8906017124801037485, 3406569241364819001])) }, infinity: false }, c: GroupAffine { x: Fp256(BigInteger256([15442965511095371475, 16233723700799040245, 2033693936526019359, 1940755394980495809])), y: Fp256(BigInteger256([9607769396956991597, 16531786910336973521, 16312419257791650835, 838503992599180484])), infinity: false } }
```

## Example witness data

See:
https://github.com/oskarth/zk-kit/commit/b6a872f7160c7c14e10a0ea40acab99cbb23c9a8

## Compiling circuits

`rln` (https://github.com/privacy-scaling-explorations/rln) repo with Circuits is contained as a submodule.

``` sh
# Update submodules
git submodule update --init --recursive

# Install rln dependencies
cd vendor/rln/ && npm install

# Build circuits
./scripts/build-circuits.sh rln

# Copy over assets
cp build/rln.r1cs ../../resources
cp build/zkeyFiles/rln-final.zkey ../../resources
cp build/zkeyFiles/rln.wasm ../../resources
```
