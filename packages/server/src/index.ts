import {} from "cryptdb-client";
import { User } from "../prisma/prisma/client";
import http from "http";

console.log("starting server");

class CryptServer {
    constructor() {
        const server = http.createServer(this.handleHttpRequest.bind(this));

        const port = 8080;
        server.listen(port, () => {
            console.log(`Server is running on port ${port}`);
        });
    }

    handleHttpRequest(req: http.IncomingMessage, res: http.ServerResponse) {
        console.log("Req", req.url);

        const url = new URL(req.url!, "http://localhost");
        console.log(url);

        switch (url.pathname) {
            case "/create": {
                res.writeHead(200);
                res.end("Create object");
                break;
            }

            default: {
                res.writeHead(404);
                res.end("Not found");
                break;
            }
        }
    }
}

const server = new CryptServer();
