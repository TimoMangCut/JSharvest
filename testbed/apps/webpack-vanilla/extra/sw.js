console.debug('JSHMARK:sw:main');
importScripts('/extra/sw-dep.js');
self.addEventListener('install', () => self.skipWaiting());
