/* @flow */

import createServer from './createServer';

const app = createServer();

app.listen(process.env.PORT || 8000, function() {
  console.log('Server started!');
});
