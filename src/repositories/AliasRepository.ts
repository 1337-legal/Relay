import BaseRepository from './BaseRepository.ts';
import type {Alias} from '../types/database';
import type {Insertable} from 'kysely';
import {jsonObjectFrom} from 'kysely/helpers/postgres';

class AliasRepository extends BaseRepository {
    async createAlias(data: Insertable<Alias>) {
        return this.database
            .insertInto('Alias')
            .values(data)
            .returningAll()
            .executeTakeFirst();
    }

    async getAliasByAddress(address: string) {
        return this.database
            .selectFrom('Alias')
            .where('Alias.address', '=', address)
            .select((eb) => [
                jsonObjectFrom(
                    eb.selectFrom('Alias as a')
                        .selectAll()
                        .whereRef('a.address', '=', 'Alias.address')
                ).as('Alias'),
                jsonObjectFrom(
                    eb.selectFrom('User')
                        .selectAll()
                        .whereRef('User.id', '=', 'Alias.userId')
                ).as('User')
            ])
            .executeTakeFirst();
    }

    async getAllByUser(publicKey: string) {
        return this.database
            .selectFrom('Alias')
            .innerJoin('User', 'Alias.userId', 'User.id')
            .where('User.publicKey', '=', publicKey)
            .select((eb) => [
                jsonObjectFrom(
                    eb.selectFrom('Alias as a')
                        .selectAll()
                        .whereRef('a.address', '=', 'Alias.address')
                ).as('Alias'),
                jsonObjectFrom(
                    eb.selectFrom('User')
                        .selectAll()
                        .whereRef('User.id', '=', 'Alias.userId')
                ).as('User')
            ])
            .execute();
    }
}

export default new AliasRepository();