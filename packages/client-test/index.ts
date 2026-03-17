import { CryptClient } from "cryptdb-client";

console.log("testing client");

const client = new CryptClient("http://localhost:8080");

client.login("stijn rogiest").then((res) => {
    console.log("logged in");
});
