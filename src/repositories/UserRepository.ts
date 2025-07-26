import type { Prisma } from '@prisma/client';

import BaseRepository from './BaseRepository';

class UserRepository extends BaseRepository {
    async findUserById(id: number) {
        return this.prisma.user.findUnique({ where: { id } });
    }

    async createUser(data: Prisma.UserCreateInput) {
        return this.prisma.user.create({ data });
    }

    async updateUser(id: number, data: Prisma.UserUpdateInput) {
        return this.prisma.user.update({ where: { id }, data });
    }

    async deleteUser(id: number) {
        return this.prisma.user.delete({ where: { id } });
    }
}

export default new UserRepository();