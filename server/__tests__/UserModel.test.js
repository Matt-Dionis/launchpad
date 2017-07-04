/* @flow */

import jwt from 'jsonwebtoken';
import type { Pad, GraphQLContext } from '../types';

import UserModel from '../UserModel';

import { createTestContext } from '../../test/testUtils';

const context = ((createTestContext(null): any): GraphQLContext);

describe('verify', () => {
  const secret =
    'mKVFmMkznAG2L5HXgizAaqCP5HrTtYePwbDDYIhkNJAeYwWHcmH8Wt93S1lwYYQ';
  const secret2 =
    'XyCg253ILEcmU4WsInmRvhqsEqEBsvuHdEF1TkIWUZxN5mztiaX6z94nWNpSjsW';
  const user = {
    id: 'test-id',
    githubUsername: 'test-username',
  };

  test('no authorization', async () => {
    expect(await UserModel.verify(null, secret)).toBeNull();
  });

  test('valid authorization', async () => {
    const authorization = `Bearer: ${jwt.sign(
      {
        sub: 'test-id',
        nickname: 'test-username',
        iat: Math.floor(Date.now() / 1000),
      },
      secret,
      {
        expiresIn: '1 min',
      },
    )}`;
    expect(await UserModel.verify(authorization, secret)).toEqual({
      id: 'test-id',
      githubUsername: 'test-username',
    });
  });

  test('invalid authorization', async () => {
    const authorization = `Bearer: ${jwt.sign(
      {
        sub: 'test-id',
        nickname: 'test-username',
      },
      secret2,
    )}`;
    expect(await UserModel.verify(authorization, secret)).toBeNull();
  });

  test('expired authorization', async () => {
    const authorization = `Bearer: ${jwt.sign(
      {
        sub: 'test-id',
        nickname: 'test-username',
        iat: Math.floor(Date.now() / 1000) - 3000,
      },
      secret,
      {
        expiresIn: '1 min',
      },
    )}`;
    expect(await UserModel.verify(authorization, secret)).toBeNull();
  });
});

describe('me', () => {
  test('anonymous', () => {
    expect(UserModel.me(context)).toBeNull();
  });

  test('logged-in', () => {
    const user = {
      id: 'test-id',
      githubUsername: 'testUsername',
    };
    expect(
      UserModel.me({
        ...context,
        user,
      }),
    ).toEqual(user);
  });
});

describe('permissions', () => {
  const anon = null;
  const user1 = {
    id: 'test-id1',
    githubUsername: 'testUsername1',
  };
  const user2 = {
    id: 'test-id2',
    githubUsername: 'testUsername2',
  };

  const padNull = (({
    id: 'pad-1',
    user: null,
  }: any): Pad);

  const padUser1 = (({
    id: 'pad-2',
    user: user1,
  }: any): Pad);

  const padUser2 = (({
    id: 'pad-3',
    user: user2,
  }: any): Pad);

  test('anonymous can not be owner', () => {
    [null, padNull, padUser1, padUser2].forEach(pad => {
      expect(UserModel.isPadOwner(anon, pad, context)).toBe(false);
    });
  });

  test('anyone but anon is owner for null pad', () => {
    expect(UserModel.isPadOwner(anon, null, context)).toBe(false);
    [user1, user2].forEach(user => {
      expect(UserModel.isPadOwner(user, null, context)).toBe(true);
    });
  });

  test('anyone but anon is owner for pad with null user', () => {
    expect(UserModel.isPadOwner(anon, padNull, context)).toBe(false);
    [user1, user2].forEach(user => {
      expect(UserModel.isPadOwner(user, padNull, context)).toBe(true);
    });
  });

  test('only user is owner for its pads', () => {
    expect(UserModel.isPadOwner(user1, padUser1, context)).toBe(true);
    expect(UserModel.isPadOwner(user2, padUser2, context)).toBe(true);
    expect(UserModel.isPadOwner(user1, padUser2, context)).toBe(false);
    expect(UserModel.isPadOwner(user2, padUser1, context)).toBe(false);
  });
});
