import BaseRepository from './BaseRepository.ts';
import type {Insertable, Updateable} from 'kysely';
import type {User} from '../types/database';

class UserRepository extends BaseRepository {
    async findUserById(id: number) {
        return this.database
            .selectFrom('User')
            .where('id', '=', id)
            .selectAll()
            .executeTakeFirst();
    }

    async findUserByPublicKey(publicKey: string) {
        return this.database
            .selectFrom('User')
            .where('publicKey', '=', publicKey)
            .selectAll()
            .executeTakeFirst();
    }

    async createUser(data: Insertable<User>) {
        return this.database
            .insertInto('User')
            .values(data)
            .returningAll()
            .executeTakeFirst();
    }

    async updateUser(id: number, data: Updateable<User>) {
        return this.database
            .updateTable('User')
            .set(data)
            .where('id', '=', id)
            .returningAll()
            .executeTakeFirst();
    }

    async deleteUser(id: number) {
        return this.database
            .deleteFrom('User')
            .where('id', '=', id)
            .returningAll();
    }
}

export default new UserRepository();