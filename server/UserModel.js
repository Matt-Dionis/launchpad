/* @flow */

import jwt from 'jsonwebtoken';
import type { User, Pad, GraphQLContext } from './types';

const UserModel = {
  filter(user: ?User, context: GraphQLContext) {
    if (user) {
      return {
        id: user.id,
        githubUsername: user.githubUsername,
      };
    } else {
      return null;
    }
  },

  async verify(authorization: ?string, secret: string): Promise<?User> {
    const bearerLength = 'Bearer: '.length;
    if (authorization && authorization.length > bearerLength) {
      const token = authorization.slice(bearerLength);
      const { ok, result } = await new Promise(resolve =>
        jwt.verify(token, secret, (err, result) => {
          if (err) {
            resolve({
              ok: false,
              result: err,
            });
          } else {
            resolve({
              ok: true,
              result,
            });
          }
        }),
      );
      if (ok) {
        return {
          id: result.sub,
          githubUsername: result.nickname,
        };
      } else {
        console.error(result);
        return null;
      }
    } else {
      return null;
    }
  },

  me(context: GraphQLContext): ?User {
    if (context.user) {
      return UserModel.filter(context.user, context);
    } else {
      return null;
    }
  },

  isPadOwner(user: ?User, pad: ?Pad, context: GraphQLContext) {
    return Boolean(user && (!pad || !pad.user || user.id === pad.user.id));
  },
};

export default UserModel;
