import type { PrismaClient } from "@prisma/client";
import PrismaDriver from '../drivers/Prisma.ts';

export default class BaseRepository {
    protected prisma: PrismaClient = PrismaDriver;
}