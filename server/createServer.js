/* @flow */

import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import { graphqlExpress, graphiqlExpress } from 'graphql-server-express';
import schema from './schema';
import type { GraphQLContext } from './types';
import MongoProvider from './MongoProvider';
import WebtaskProvider from './WebtaskProvider';
import UserModel from './UserModel';

type Secrets = {
  WT_TOKEN: string,
  WT_API: string,
  MONGODB_URL: string,
  AUTH0_SECRET: string,
  WT_NO_PROXY: ?string,
  WT_SINGLE_TENANT_CONTAINER: ?string,
};

function getFromEnv(key): string {
  const value = process.env[key];
  if (!value) {
    throw new Error(`Missing environment variable: '${key}'`);
  }
  return value || null;
}

function getFromEnvNullable(key): ?string {
  const value = process.env[key];
  return value || null;
}

const secrets: Secrets = {
  WT_TOKEN: getFromEnv('WT_TOKEN'),
  WT_API: getFromEnv('WT_API'),
  MONGODB_URL: getFromEnv('MONGODB_URL'),
  AUTH0_SECRET: getFromEnv('AUTH0_SECRET'),
  WT_NO_PROXY: getFromEnvNullable('WT_NO_PROXY'),
  WT_SINGLE_TENANT_CONTAINER: getFromEnvNullable('WT_SINGLE_TENANT_CONTAINER'),
};

export default function createServer() {
  const app = express();

  app.options('/', cors());
  app.use(
    '/',
    cors(),
    bodyParser.json(),
    graphqlExpress(async request => {
      const user = await UserModel.verify(
        request.headers['authorization'],
        secrets.AUTH0_SECRET,
      );
      return {
        schema: schema,
        context: ({
          user,
          webtaskToken: secrets.WT_TOKEN,
          mongo: new MongoProvider(secrets.MONGODB_URL),
          webtask: new WebtaskProvider({
            token: secrets.WT_TOKEN,
            webtaskUrl: secrets.WT_API,
            singleTenantContainer: secrets.WT_SINGLE_TENANT_CONTAINER,
            noProxy: Boolean(secrets.WT_NO_PROXY),
          }),
        }: GraphQLContext),
        rootValue: {},
      };
    }),
  );

  app.use(
    '/graphiql',
    graphiqlExpress({
      endpointURL: '/',
    }),
  );

  return app;
}
