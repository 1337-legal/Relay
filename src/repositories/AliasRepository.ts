import BaseRepository from './BaseRepository';

class AliasRepository extends BaseRepository {
    async findAliasByAddress(address: string) {
        return this.prisma.alias.findUnique({
            where: { address },
            include: { user: true },
        });
    }
}

export default new AliasRepository();