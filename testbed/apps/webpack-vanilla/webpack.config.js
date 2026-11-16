const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');

// Chunks are left unnamed on purpose: most production builds ship numeric,
// content-hashed chunk files that nothing but the runtime chunk map refers to.
module.exports = {
  entry: './src/index.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'static/js/[name].[contenthash:8].js',
    chunkFilename: 'static/js/[id].[contenthash:8].chunk.js',
    publicPath: '/',
    clean: true,
  },
  plugins: [new HtmlWebpackPlugin({ template: './src/index.html', inject: 'body' })],
};
