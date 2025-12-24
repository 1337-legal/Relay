import BaseRepository from './BaseRepository.ts';

class AliasRepository extends BaseRepository {
    async getUserByAlias(alias: string) {
        return this.database
            .selectFrom('Alias')
            .innerJoin('User', 'Alias.userId', 'User.id')
            .where('Alias.address', '=', alias)
            .selectAll('User')
            .executeTakeFirst();
    }

    async getAliasByAddress(address: string) {
        return this.database
            .selectFrom('Alias')
            .where('Alias.address', '=', address)
            .selectAll()
            .executeTakeFirst();
    }
}

export default new AliasRepository();