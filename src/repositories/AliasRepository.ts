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
}

export default new AliasRepository();