import Database from "../drivers/Database.ts";

export default class BaseRepository {
    protected database = Database;
}