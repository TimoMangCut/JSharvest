const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');

// A production build: minified, constants folded, chunks numbered and
// content-hashed, as the endpoint extractor meets them in the wild.
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
