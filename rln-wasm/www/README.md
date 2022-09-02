# RLN WASM EXAMPLE APP

How to compile zerokit for wasm and see example code:
1. Make sure you have nodejs installed and the `build-essential` package if using ubuntu.
2. Install wasm-pack
```
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```
3. Compile zerokit for `wasm32-unknown-unknown`:
```
cd rln-wasm
wasm-pack build --release
```
4. Launch example app
```
cd www
npm install
npm start
```
5. Browse http://localhost:8080 and open the developer tools to see console logs