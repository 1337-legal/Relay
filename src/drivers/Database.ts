import {Kysely, PostgresDialect} from 'kysely';
import type {DB} from '../types/database.js';
import {Pool} from 'pg';

const Database = new Kysely<DB>({
    dialect: new PostgresDialect({
        pool: new Pool({
            connectionString: process.env.DATABASE_URL,
        }),
    }),
});

export default Database;