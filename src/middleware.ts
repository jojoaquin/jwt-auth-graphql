import { GraphQLError } from "graphql";
import { verify } from "jsonwebtoken";
import { prisma } from "./index";
import { createToken } from "./utils/createToken";

const isAuth = async (
  resolve: any,
  parent: any,
  args: any,
  context: any,
  info: any
) => {
  const accessToken = context.req.cookies["access-token"];
  const refreshToken = context.req.cookies["refresh-token"];

  if (!accessToken && !refreshToken) {
    throw new GraphQLError("Refresh and access token is not provided", {
      extensions: {
        code: "UNAUTHORIZED",
      },
    });
  }

  if (!refreshToken) {
    throw new GraphQLError("Refresh token is not provided", {
      extensions: {
        code: "UNAUTHORIZED",
      },
    });
  }

  let data;
  try {
    data = verify(refreshToken, process.env.REFRESH_TOKEN_SECRET!) as any;
    context.req.userId = data.userId;
  } catch (e) {
    throw new GraphQLError("Refresh token is expired");
  }

  const user = await prisma.users.findUnique({ where: { id: data.userId } });

  if (!user || user.tokenVersion !== data.tokenVersion) {
    context.res.clearCookie("access-token");
    context.res.clearCookie("refresh-token");
    throw new GraphQLError("Refresh token is not valid with token version", {
      extensions: {
        code: "UNAUTHORIZED",
      },
    });
  }

  if (!accessToken) {
    const tokens = createToken(user);
    context.res.cookie("access-token", tokens.accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    });
    context.res.cookie("refresh-token", tokens.refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    });
  }

  try {
    const data = verify(accessToken, process.env.ACCESS_TOKEN_SECRET!) as any;
    context.req.userId = data.userId;
  } catch {}
  return resolve(parent, args, context, info);
};

export const isAuthMiddleware = {
  Query: {
    me: isAuth,
  },
};
