/* @flow */

import Hashids from 'hashids';
import UserModel from './UserModel';
import { STARTER_CODE } from './code';
import type {
  Pad,
  GraphQLContext,
  PadInput,
  Context,
  Dependency,
  PadInputWithoutId,
  PadMetadataInput,
} from './types';

const STARTER_DEPLOYED_URL = `https://wt-launchpad.it.auth0.com/api/run/launchpad/launchpad-starter-code`;
const ID_GENERATOR = new Hashids(
  'Apollo Launchpad',
  8,
  'bcdfghjklmnpqrstvwxz0123456789',
);

const PadModel = {
  filter(pad: Pad, context: GraphQLContext): Pad {
    const user = UserModel.me(context);
    let padContext;
    let token = null;
    if (pad.context) {
      if (UserModel.isPadOwner(user, pad, context)) {
        padContext = pad.context;
        token = pad.token;
      } else if (pad.context) {
        padContext = pad.context.map(({ key }) => ({ key }));
      } else {
        padContext = [];
      }
    }

    let draft = null;
    if (pad.draft && UserModel.isPadOwner(user, pad.draft, context)) {
      draft = {
        ...PadModel.filter(pad.draft, context),
        title: pad.title,
        description: pad.description,
        defaultQuery: pad.defaultQuery,
        defaultVariables: pad.defaultVariables,
        token,
      };
    }

    return {
      id: pad.id,
      title: pad.title,
      description: pad.description,
      code: pad.code,
      deployedCode: pad.deployedCode,
      url: pad.url,
      user: UserModel.filter(pad.user, context),
      dependencies: pad.dependencies,
      context: padContext,
      draft,
      defaultQuery: pad.defaultQuery,
      defaultVariables: pad.defaultVariables,
      token,
    };
  },

  async generateId(context: GraphQLContext): Promise<string> {
    return ID_GENERATOR.encode(
      new Date().getTime() - new Date(2017, 1, 1).getTime(),
    );
  },

  async empty(context: GraphQLContext, id: ?string = null): Promise<Pad> {
    if (!id) {
      id = await PadModel.generateId(context);
    }
    return PadModel.filter(
      {
        id,
        title: null,
        description: null,
        code: STARTER_CODE,
        deployedCode: null,
        url: null,
        user: UserModel.me(context),
        context: [],
        dependencies: [],
        defaultQuery: null,
        defaultVariables: null,
        token: null,
        draft: {
          id: `${id}_draft`,
          title: null,
          description: null,
          code: STARTER_CODE,
          deployedCode: null,
          url: STARTER_DEPLOYED_URL,
          user: UserModel.me(context),
          context: [],
          dependencies: [],
          draft: null,
          defaultQuery: null,
          defaultVariables: null,
          token: null,
        },
      },
      context,
    );
  },

  async getById(id: string, context: GraphQLContext): Promise<?Pad> {
    const collection = await context.mongo.pads();
    const pad = await collection.findOne({
      id,
    });
    if (pad) {
      return PadModel.filter(pad, context);
    } else {
      return null;
    }
  },

  async listMyPads(context: GraphQLContext): Promise<Array<Pad>> {
    const collection = await context.mongo.pads();
    const user = await UserModel.me(context);
    if (user) {
      const pads = await collection
        .find({
          'user.id': user.id,
        })
        .toArray();
      return pads.map(pad => PadModel.filter(pad, context));
    } else {
      return [];
    }
  },

  async resolveDependencies(
    dependencies: Array<string>,
    oldDependencies: Array<Dependency>,
    context: GraphQLContext,
  ): Promise<
    | {
      ok: true,
      resolvedDependencies: Array<Dependency>,
    }
    | { ok: false, reason: string },
  > {
    let resolvedDependencies = await context.webtask.resolveDependencies(
      dependencies,
      oldDependencies,
    );

    const missingDependencies = resolvedDependencies.filter(
      dep => !dep.version,
    );
    if (missingDependencies.length > 0) {
      const missingNames = missingDependencies
        .map(dependency => dependency.name)
        .join(', ');
      return {
        ok: false,
        reason: `Could not resolve packages: ${missingNames}.`,
      };
    }

    return {
      ok: true,
      resolvedDependencies,
    };
  },

  async deploy(
    {
      id,
      type,
      deployedCode,
      context: padContext,
      dependencies,
    }: {
      id: string,
      type: 'depl' | 'draft',
      deployedCode: string,
      context: Array<Context>,
      dependencies: Array<Dependency>,
    },
    context: GraphQLContext,
  ): Promise<{ ok: true, url: string } | { ok: false }> {
    const result = await context.webtask.deploy({
      containerId: id,
      name: type,
      code: deployedCode,
      context: padContext,
      dependencies,
    });

    if (result.ok) {
      return {
        ok: true,
        url: result.url,
      };
    } else {
      return result;
    }
  },

  async create(
    input: PadInputWithoutId,
    context: GraphQLContext,
  ): Promise<{ ok: true, pad: Pad } | { ok: false, reason: string }> {
    const id = await PadModel.generateId(context);
    return PadModel.update(
      {
        ...input,
        id,
      },
      context,
    );
  },

  async update(
    {
      id,
      code,
      deployedCode,
      context: padContext = [],
      dependencies = [],
    }: PadInput,
    context: GraphQLContext,
  ): Promise<{ ok: true, pad: Pad } | { ok: false, reason: string }> {
    const pad = await PadModel.getById(id, context);

    let token;
    if (pad && pad.token) {
      token = pad.token;
      context.webtask.addToken(id, pad.token);
    } else {
      token = await context.webtask.getToken(id);
    }

    const user = UserModel.me(context);
    if (!UserModel.isPadOwner(user, pad, context)) {
      return {
        ok: false,
        reason: 'User can only update their own pads',
      };
    }

    const oldDependencies = (pad && pad.dependencies) || [];
    const dependencyResult = await PadModel.resolveDependencies(
      dependencies,
      oldDependencies,
      context,
    );
    if (!dependencyResult.ok) {
      return dependencyResult;
    }

    const updatedPad = {
      id,
      title: (pad && pad.title) || null,
      description: (pad && pad.description) || null,
      code,
      url: (pad && pad.url) || null,
      deployedCode,
      context: padContext,
      dependencies: dependencyResult.resolvedDependencies,
      user,
      token,
      draft: null,
      defaultQuery: (pad && pad.defaultQuery) || null,
      defaultVariables: (pad && pad.defaultVariables) || null,
    };

    return savePad(updatedPad, context);
  },

  // Forks a pad. When forking, we want to:
  // 1. Generate a new ID and new pad object, generate new token
  // 2. If we own the pad being forked, copy the secrets; otherwise, only copy the keys
  // 3. Copy all the rest of the data
  async fork(id: string, context: GraphQLContext) {
    const pad = await PadModel.getById(id, context);
    const newId = await PadModel.generateId(context);
    const user = await UserModel.me(context);
    const token = await context.webtask.getToken(id);
    if (pad) {
      let padContext = pad.context || [];
      if (!UserModel.isPadOwner(user, pad, context)) {
        padContext = padContext.map(({ key }) => ({
          key,
          value: '',
        }));
      }
      if (pad && pad.code && pad.deployedCode) {
        const newPad = {
          ...pad,
          id: newId,
          context: padContext,
          draft: null,
          token,
          user,
        };
        return savePad(newPad, context);
      }
    }

    return {
      ok: false,
      reason: 'Can not fork pad that does not exist',
    };
  },

  async updateDraft(
    {
      id,
      code,
      deployedCode,
      context: padContext = [],
      dependencies = [],
    }: PadInput,
    context: GraphQLContext,
  ): Promise<{ ok: true, pad: Pad } | { ok: false, reason: string }> {
    let pad = await PadModel.getById(id, context);

    const user = UserModel.me(context);
    if (pad && pad.user && !UserModel.isPadOwner(user, pad, context)) {
      return {
        ok: false,
        reason: 'User can only update their own pads',
      };
    }

    let token;
    if (pad && pad.token) {
      context.webtask.addToken(id, pad.token);
      token = pad.token;
    } else {
      token = await context.webtask.getToken(id);
    }

    const oldDependencies = (pad && pad.dependencies) || [];
    const dependencyResult = await PadModel.resolveDependencies(
      dependencies,
      oldDependencies,
      context,
    );
    if (!dependencyResult.ok) {
      return dependencyResult;
    }

    const draftId = `${id}_draft`;
    const result = await PadModel.deploy(
      {
        id,
        type: 'draft',
        deployedCode,
        context: padContext,
        dependencies: dependencyResult.resolvedDependencies,
      },
      context,
    );

    if (result.ok) {
      pad = pad || {
        id: id,
        title: null,
        description: null,
        code: null,
        deployedCode: null,
        url: null,
        user,
        context: [],
        dependencies: [],
        draft: null,
        defaultQuery: null,
        defaultVariables: null,
      };

      const updatedPad = {
        ...pad,
        id,
        token,
        draft: {
          id: draftId,
          code,
          url: result.url,
          deployedCode,
          context: padContext,
          dependencies: dependencyResult.resolvedDependencies,
          user,
          draft: null,
          defaultQuery: pad.defaultQuery,
          defaultVariables: pad.defaultVariables,
          title: pad.title,
          description: pad.description,
          token,
        },
      };
      const collection = await context.mongo.pads();
      await collection.update({ id }, updatedPad, { upsert: true });

      return {
        ok: true,
        pad: PadModel.filter(updatedPad, context),
      };
    } else {
      return {
        ok: false,
        reason: 'Could not push code to webtask',
      };
    }
  },

  async deleteDraft(
    id: string,
    context: GraphQLContext,
  ): Promise<{ ok: true, pad: Pad } | { ok: false, reason: string }> {
    let pad = await PadModel.getById(id, context);

    if (!pad) {
      return {
        ok: false,
        reason: 'Pad does not exist',
      };
    }

    const user = UserModel.me(context);

    let updatedPad;
    if (UserModel.isPadOwner(user, pad, context)) {
      updatedPad = {
        ...pad,
        id,
        draft: null,
      };

      const collection = await context.mongo.pads();
      await collection.update({ id }, updatedPad, { upsert: true });
    } else {
      updatedPad = pad;
    }

    return {
      ok: true,
      pad: PadModel.filter(updatedPad, context),
    };
  },

  async updatePadMetadata(
    { id, ...input }: PadMetadataInput,
    context: GraphQLContext,
  ): Promise<{ ok: true, pad: Pad } | { ok: false, reason: string }> {
    let pad = await PadModel.getById(id, context);
    const user = UserModel.me(context);

    if (!pad) {
      pad = await PadModel.empty(context, id);
    }

    if (!UserModel.isPadOwner(user, pad, context)) {
      return {
        ok: false,
        reason: 'User can only update their own pads',
      };
    }

    const collection = await context.mongo.pads();

    await collection.update(
      { id },
      {
        $set: {
          id,
          ...input,
        },
      },
      {
        upsert: true,
      },
    );

    return {
      ok: true,
      pad: PadModel.filter(
        {
          ...pad,
          ...input,
        },
        context,
      ),
    };
  },
};

async function savePad(pad: Pad, context: GraphQLContext) {
  const collection = await context.mongo.pads();
  if (pad.deployedCode) {
    const result = await PadModel.deploy(
      {
        id: pad.id,
        type: 'depl',
        deployedCode: pad.deployedCode,
        context: pad.context || [],
        dependencies: pad.dependencies || [],
      },
      context,
    );

    if (result.ok) {
      const updatedPad = {
        id: pad.id,
        title: (pad && pad.title) || null,
        description: (pad && pad.description) || null,
        code: pad.code,
        url: result.url,
        deployedCode: pad.deployedCode,
        context: pad.context,
        dependencies: pad.dependencies,
        user: pad.user,
        token: pad.token,
        draft: null,
        defaultQuery: (pad && pad.defaultQuery) || null,
        defaultVariables: (pad && pad.defaultVariables) || null,
      };
      await collection.update({ id: pad.id }, updatedPad, { upsert: true });

      return {
        ok: true,
        pad: PadModel.filter(updatedPad, context),
      };
    } else {
      return {
        ok: false,
        reason: 'Could not push code to webtask',
      };
    }
  } else {
    return {
      ok: false,
      reason: 'Could not push code to webtask',
    };
  }
}

export default PadModel;
