const CopyWebpackPlugin = require("copy-webpack-plugin");
const path = require('path');
const webpack = require('webpack')

module.exports = {
  entry: "./bootstrap.js",
  output: {
    path: path.resolve(__dirname, "dist"),
    filename: "bootstrap.js",
  },
  mode: "development",
  resolve: {
    fallback: {
      buffer: require.resolve('buffer/'),
    },
  },
  plugins: [
    new CopyWebpackPlugin({
      patterns: ['index.html'],
    }),
    new webpack.ProvidePlugin({
      Buffer: ['buffer', 'Buffer'],
    }),
  ],
  experiments: {
    asyncWebAssembly: true,
  },

};
