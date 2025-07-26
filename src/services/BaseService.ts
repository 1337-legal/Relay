class BaseService {
    protected checkEnvironment(variables: string[]): void {
        for (const variable of variables) {
            if (!process.env[variable]) {
                throw new Error(`${variable} environment variable is not set`);
            }
        }
    }
}

export default BaseService;