import BaseRepository from './BaseRepository.ts';
import type {Alias} from '../types/database';
import type {Insertable} from 'kysely';

class AliasRepository extends BaseRepository {
    async createAlias(data: Insertable<Alias>) {
        /*return this.prisma.alias.create({
            data,
        });*/
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
            .innerJoin('User', 'Alias.userId', 'User.id')
            .select([
                'Alias.id as aliasId',
                'Alias.address as aliasAddress',
                'Alias.userId',
                'Alias.createdAt as aliasCreatedAt',
                'Alias.updatedAt as aliasUpdatedAt',
                'User.id as userId',
                'User.address as userAddress',
                'User.publicKey',
                'User.pgpPublicKey',
                'User.role',
                'User.createdAt as userCreatedAt',
                'User.updatedAt as userUpdatedAt'
            ])
            .executeTakeFirst();
    }

    async getAllByUser(publicKey: string) {
        return this.database
            .selectFrom('Alias')
            .innerJoin('User', 'Alias.userId', 'User.id')
            .where('User.publicKey', '=', publicKey)
            .select([
                'Alias.id as aliasId',
                'Alias.address as aliasAddress',
                'Alias.userId',
                'Alias.createdAt as aliasCreatedAt',
                'Alias.updatedAt as aliasUpdatedAt',
                'User.id as userId',
                'User.address as userAddress',
                'User.publicKey',
                'User.pgpPublicKey',
                'User.role',
                'User.createdAt as userCreatedAt',
                'User.updatedAt as userUpdatedAt'
            ])
            .execute();
    }
}

export default new AliasRepository();