import { CryptClient } from "cryptdb-client";

console.log("testing client");

const client = new CryptClient("TestingApp", "http://localhost:8080");

client.loginUsingPassword("stijnrogiest12", "Vrijdag1@").then((v) => {
    console.log("logged in", v);
});

// client.loginUsingPassword("stijnrogiest3", "Vrijdag1@").then((v) => {
//     console.log("logged in", v);
// });

// client.login("stijn rogiest").then((res) => {
//     console.log("logged in");
// });
