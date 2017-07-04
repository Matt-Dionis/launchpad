/* @flow */

import { fromPairs } from 'lodash';
import { randomString } from 'cryptiles';
import type { Dependency, Context } from '../server/types';
import MongoProvider from '../server/MongoProvider';

export class MockWebtaskProvider {
  async getToken(containerId: string): Promise<string> {
    return `FAKE_TOKEN_${containerId}`;
  }

  addToken() {}

  async query(): Promise<{ ok: boolean, response: any }> {
    return { ok: true, response: null };
  }

  async resolveDependency(name: string): Promise<?string> {
    return '0.0.0-FAKE';
  }

  async resolveDependencies(
    dependencies: Array<string>,
    oldDependencies: ?Array<Dependency>,
  ): Promise<Array<Dependency>> {
    oldDependencies = oldDependencies || [];
    const packageMap = fromPairs(
      oldDependencies.map(({ name, version }) => [name, version]),
    );
    if (!dependencies.find(name => name === 'graphql')) {
      dependencies = ['graphql', ...dependencies];
    }
    const result = await Promise.all(
      dependencies.map(async name => {
        if (packageMap[name]) {
          return {
            name,
            version: packageMap[name],
          };
        } else {
          const version = await this.resolveDependency(name);
          if (version) {
            return {
              name,
              version,
            };
          } else {
            return {
              name,
              version: null,
            };
          }
        }
      }),
    );
    return result;
  }

  async ensureDependencies(): Promise<{ ok: boolean }> {
    return { ok: true };
  }

  async deploy({
    containerId,
    name,
    code,
    context,
    dependencies,
  }: {
    containerId: string,
    name: string,
    code: string,
    context: Array<Context>,
    dependencies: Array<Dependency>,
  }): Promise<{ ok: true, url: string } | { ok: false }> {
    let url;
    if (name === 'draft') {
      url = `https://${containerId}.lp.gql.zone/draft/graphql`;
    } else {
      url = `https://${containerId}.lp.gql.zone/graphql`;
    }
    return {
      ok: true,
      url,
    };
  }
}

export class MockMongoProvider {}

export function createTestContext(mongoUrl: ?string) {
  let mongo;
  if (mongoUrl) {
    mongo = new MongoProvider(mongoUrl);
  } else {
    mongo = new MockMongoProvider();
  }
  return {
    webtaskToken: 'TEST_WEBTASK_TOKEN',
    mongo,
    webtask: new MockWebtaskProvider(),
    user: null,
  };
}

export function createTestDatabaseName() {
  return `testdb_${randomString(8)}`;
}
