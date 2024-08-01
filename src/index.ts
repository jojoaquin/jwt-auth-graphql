import express, { NextFunction, Request, Response } from "express";
import dotenv from "dotenv";
import { ApolloServer } from "@apollo/server";
import { expressMiddleware } from "@apollo/server/express4";
import cors from "cors";
import gql from "gql-tag";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import { createToken } from "./utils/createToken";
import cookieParser from "cookie-parser";
import { makeExecutableSchema } from "@graphql-tools/schema";
import { applyMiddleware } from "graphql-middleware";
import { isAuthMiddleware } from "./middleware";
import { JwtPayload, verify } from "jsonwebtoken";

dotenv.config();
export const prisma = new PrismaClient();

const graphqlAuth = (req: Request, res: Response, next: NextFunction) => {
  if (req.header("x-auth-token") !== process.env.AUTH_TOKEN_KEY) {
    return res.status(401).json({
      message: "Unauthorized",
    });
  } else {
    return next();
  }
};

(async () => {
  const app = express();

  const typeDefs = gql`
    type User {
      id: Int!
      name: String!
      email: String!
    }

    type Query {
      hello: String!
      me: User
    }

    type Mutation {
      register(username: String!, email: String!, password: String!): Boolean!
      login(email: String!, password: String!): Boolean!
      logout: Boolean!
      logoutAllDevice: Boolean!
    }
  `;

  const resolvers = {
    Query: {
      hello: () => {
        return "Hello World";
      },
      me: async (_: any, __: any, { req }: any) => {
        const userId = req.userId;

        if (!userId) {
          return null;
        }

        const user = await prisma.users.findUnique({
          where: { id: userId },
        });

        return user;
      },
    },
    Mutation: {
      register: async (_: any, { username, email, password }: any) => {
        const bcryptPassword = await bcrypt.hash(password, 11);
        await prisma.users.create({
          data: {
            name: username,
            email: email,
            password: bcryptPassword,
          },
        });
        return true;
      },
      login: async (_: any, { email, password }: any, ctx: any) => {
        const user = await prisma.users.findUnique({ where: { email } });

        if (!user) {
          return false;
        }

        const isPassValid = await bcrypt.compare(password, user.password!);

        if (!isPassValid) {
          return false;
        }

        const { accessToken, refreshToken } = createToken(user);

        ctx.res.cookie("access-token", accessToken, {
          httpOnly: true,
          secure: true,
          sameSite: "strict",
          maxAge: 24 * 60 * 60 * 1000,
        });
        ctx.res.cookie("refresh-token", refreshToken, {
          httpOnly: true,
          secure: true,
          sameSite: "strict",
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        return true;
      },
      logout: (_: any, __: any, { req, res }: { req: any; res: Response }) => {
        const accessToken = req.cookies["access-token"];
        const refreshToken = req.cookies["refresh-token"];
        if (!accessToken && !refreshToken) {
          return false;
        }
        res.clearCookie("access-token");
        res.clearCookie("refresh-token");
        return true;
      },
      logoutAllDevice: async (_: any, __: any, { req, res }: any) => {
        const refreshToken = req.cookies["refresh-token"];

        if (!refreshToken) {
          return false;
        }

        try {
          const data = verify(
            refreshToken,
            process.env.REFRESH_TOKEN_SECRET!
          ) as JwtPayload;
          await prisma.users.update({
            where: {
              id: data.userId!,
            },
            data: {
              tokenVersion: data.tokenVersion + 1,
            },
          });

          res.clearCookie("access-token");
          res.clearCookie("refresh-token");
          return true;
        } catch {
          return false;
        }
      },
    },
  };

  const schema = makeExecutableSchema({
    typeDefs,
    resolvers,
  });

  const schemaWithMiddleware = applyMiddleware(schema, isAuthMiddleware);

  const server = new ApolloServer({
    schema: schemaWithMiddleware,
  });

  await server.start();

  app.get("/", (_, res: Response) => {
    return res.json({
      message: "Hello world",
    });
  });

  app.use(
    "/graphql",
    graphqlAuth,
    cors(),
    cookieParser(),
    express.json(),
    expressMiddleware(server, {
      context: async ({ req, res }: any) => ({
        req,
        res,
      }),
    })
  );

  app.listen(process.env.PORT, () => {
    console.log(
      `🚀 Server run in http://localhost:${process.env.PORT}/graphql`
    );
  });
})();
